//! Два устройства в одном процессе, без сети и без диска: вся жизнь переписки так, как её
//! видит ядро.
//!
//! Запуск:
//!
//! ```text
//! cargo run --example two_devices
//! ```
//!
//! Что здесь показано. Ядро не делает ввода-вывода: на каждое событие (`IncomingEvent`) оно
//! возвращает список действий (`Vec<Action>`), и *приложение* их исполняет — сохраняет в
//! Keychain, шлёт на сервер, показывает уведомление. В этом примере приложение, сервер и
//! Keychain — три маленькие структуры ниже, поэтому видно, куда в конечном счёте приходит
//! каждый байт. В iOS ровно те же действия исполняет Swift, в Android — Kotlin; ядро не знает
//! разницы.
//!
//! Читать сверху вниз: `Device` (устройство: ядро + его «Keychain»), `Server` (хранит бандлы
//! ключей, подписывает сертификаты отправителя, носит почту), `execute` (исполнитель действий —
//! то, чем в реальном приложении является главный цикл), `main` (сценарий).

use std::collections::HashMap;

use construct_core::crypto::client_api::ClassicClient;
use construct_core::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use construct_core::crypto::sealed_sender::{SenderCertificate, build_cert_sign_payload};
use construct_core::crypto::suites::classic::ClassicSuiteProvider;
use construct_core::orchestration::orchestrator::{KyberBundleKeys, Orchestrator, SessionBundle};
use construct_core::orchestration::{Action, IncomingEvent};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rand::rngs::OsRng;

// ─────────────────────────────────────────────────────────────────────────────
// Устройство
// ─────────────────────────────────────────────────────────────────────────────

/// Одно устройство: ядро и то, что приложение хранит для него.
///
/// `Orchestrator` — это и есть ядро (в UDL он виден как `OrchestratorCore`). Он владеет
/// ключами и сессиями, но *не* хранит их между запусками: всё, что должно пережить перезапуск,
/// ядро отдаёт действием `SaveToSecureStore`, и приложение кладёт это в Keychain. Здесь Keychain
/// — обычный `HashMap`.
struct Device {
    /// Человекочитаемое имя — только для печати.
    label: &'static str,
    /// Идентификатор устройства: первые 16 байт SHA-256 от identity-ключа, hex. Это тот
    /// `contact_id`, которым устройства называют друг друга во всех вызовах ядра.
    id: String,
    core: Orchestrator,
    /// «Keychain»: слот → байты. Ключ `String`, потому что `SecureStoreSlot` — enum с данными,
    /// и для примера проще печатать его `Debug`-представление, чем выводить `Hash` для него.
    secure_store: HashMap<String, Vec<u8>>,
    /// «База ACK»: id сообщений, которые устройство уже обработало. Ядро держит такой же список
    /// в памяти, а это — его долговечная копия, которую оно просит сохранить (`PersistAck`).
    ack_db: Vec<String>,
}

impl Device {
    /// Регистрация устройства — то, что приложение делает один раз при первом запуске.
    fn new(label: &'static str) -> Self {
        // `ClassicClient::<ClassicSuiteProvider>` — менеджер ключей и сессий на X25519 / Ed25519
        // / ChaCha20-Poly1305. Постквантовая часть (ML-KEM, ML-DSA) добавляется поверх него
        // ядром, а не заменой провайдера — см. AGENTS.md, «Crypto-Agility».
        let client = ClassicClient::<ClassicSuiteProvider>::new().expect("key generation");
        // Имя пока неизвестно: id выводится из identity-ключа, который только что родился.
        let mut core = Orchestrator::new(client, "pending".to_string());

        // Гибридный ключ подписи (Ed25519 + ML-DSA-65): им подписываются Kyber-преключи.
        core.ensure_hybrid_signature_key()
            .expect("hybrid signature key");
        // Первый Kyber SPK (ML-KEM-1024). Ротация двухфазная — begin / commit — потому что в
        // реальном приложении между ними стоит загрузка на сервер, и если она не удалась,
        // делается rollback, а старый ключ продолжает жить.
        core.begin_kyber_spk_rotation().expect("kyber spk");
        assert!(core.commit_kyber_spk_rotation());

        let identity = core
            .get_registration_bundle_fields()
            .expect("registration bundle")
            .identity_public;
        let id = construct_core::device_id::derive_device_id(&identity);
        core.set_my_user_id(id.clone());

        Self {
            label,
            id,
            core,
            secure_store: HashMap::new(),
            ack_db: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Сервер
// ─────────────────────────────────────────────────────────────────────────────

/// Письмо в очереди сервера: кому, от кого, байты и сертификат отправителя.
///
/// В настоящем протоколе сертификат лежит *внутри* запечатанного конверта (sealed sender), и
/// сервер его не видит — он знает только получателя. Здесь конверта нет, поэтому сертификат
/// едет рядом; для ядра получателя разницы нет: оно получает его в `MessageReceived`.
struct Delivery {
    to: String,
    from: String,
    message_id: String,
    content_type: u8,
    payload: Vec<u8>,
    certificate: SenderCertificate,
}

/// То, что устройство выгружает при регистрации, и что сервер отдаёт тому, кто хочет открыть
/// с ним сессию.
struct Registration {
    x3dh: X3DHPublicKeyBundle,
    kyber_spk: construct_core::crypto::kyber_prekeys::KyberPrekeyUpload,
    /// Одноразовые Kyber-преключи: сервер отдаёт по одному и забывает — в этом их смысл.
    kyber_otpks: Vec<construct_core::crypto::kyber_prekeys::KyberPrekeyUpload>,
    hybrid_identity_key: Vec<u8>,
    hybrid_identity_signature: Vec<u8>,
}

/// Сервер: хранит бандлы, подписывает сертификаты отправителя, носит почту.
///
/// Чего сервер *не* умеет — важнее того, что умеет: у него нет ни одного приватного ключа
/// устройств и он не может прочитать ни одного `payload` ниже.
struct Server {
    /// Ключ, которым сервер подписывает сертификаты отправителя. Устройства доверяют его
    /// публичной половине (`set_trusted_server_keys`) — иначе первое сообщение от незнакомца
    /// не откроет сессию.
    key: SigningKey,
    registrations: HashMap<String, Registration>,
    mailbox: Vec<Delivery>,
}

impl Server {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self {
            key: SigningKey::from_bytes(&seed),
            registrations: HashMap::new(),
            mailbox: Vec::new(),
        }
    }

    fn verifying_key(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }

    /// Регистрация: устройство выгружает всё публичное, что нужно другим, чтобы писать ему
    /// первыми. Приватные половины остаются в `device.core`.
    fn register(&mut self, device: &mut Device) {
        let x3dh = device
            .core
            .get_registration_bundle_fields()
            .expect("registration bundle");
        let hybrid = device
            .core
            .hybrid_signature_public_key()
            .expect("hybrid key was ensured in Device::new");
        // Кросс-подпись: identity-ключ (Ed25519) подписывает гибридный ключ, чтобы никто не мог
        // подменить гибридную половину, оставив классическую.
        let bind = Orchestrator::build_hybrid_identity_bind_message(&hybrid);
        let binding = device.core.sign_with_device_key(&bind).expect("sign");
        let kyber_spk = device
            .core
            .current_kyber_spk_upload()
            .expect("spk")
            .expect("spk was committed in Device::new");
        let kyber_otpks = device
            .core
            .generate_kyber_one_time_prekeys(3)
            .expect("otpks");

        println!(
            "  [server] {} зарегистрировано: identity {} байт, Kyber SPK {} байт, {} одноразовых",
            device.label,
            x3dh.identity_public.len(),
            kyber_spk.public_key.len(),
            kyber_otpks.len()
        );
        self.registrations.insert(
            device.id.clone(),
            Registration {
                x3dh,
                kyber_spk,
                kyber_otpks,
                hybrid_identity_key: hybrid,
                hybrid_identity_signature: binding,
            },
        );
    }

    /// Выдать бандл устройства `id` тому, кто хочет открыть с ним сессию. Одноразовый преключ
    /// при этом *расходуется*: второй запрос получит следующий, а когда они кончатся — `None`,
    /// и сессия откроется только по SPK.
    fn fetch_bundle(&mut self, id: &str) -> Result<SessionBundle, String> {
        let reg = self
            .registrations
            .get_mut(id)
            .ok_or_else(|| format!("no such device: {id}"))?;
        let otpk = (!reg.kyber_otpks.is_empty()).then(|| reg.kyber_otpks.remove(0));
        let kyber = KyberBundleKeys {
            pre_key_id: Some(reg.kyber_spk.key_id),
            pre_key_public: Some(reg.kyber_spk.public_key.clone()),
            pre_key_created_at: Some(reg.kyber_spk.created_at),
            pre_key_signature: Some(reg.kyber_spk.signature.clone()),
            pre_key_hybrid_signature: Some(reg.kyber_spk.hybrid_signature.clone()),
            one_time_prekey_id: otpk.as_ref().map(|k| k.key_id),
            one_time_prekey_public: otpk.as_ref().map(|k| k.public_key.clone()),
            one_time_prekey_created_at: otpk.as_ref().map(|k| k.created_at),
            one_time_prekey_signature: otpk.as_ref().map(|k| k.signature.clone()),
            one_time_prekey_hybrid_signature: otpk.as_ref().map(|k| k.hybrid_signature.clone()),
            hybrid_identity_key: Some(reg.hybrid_identity_key.clone()),
            hybrid_identity_signature: Some(reg.hybrid_identity_signature.clone()),
        };
        Ok(SessionBundle {
            x3dh: reg.x3dh.clone(),
            kyber,
        })
    }

    /// Сертификат отправителя: сервер ручается, что identity-ключ принадлежит устройству с
    /// таким id. Получатель проверяет подпись ключом сервера и только тогда открывает сессию
    /// от первого сообщения незнакомца.
    fn certify(&self, device: &Device) -> SenderCertificate {
        let identity_key = self
            .registrations
            .get(&device.id)
            .expect("registered")
            .x3dh
            .identity_public
            .clone();
        let now = construct_core::utils::time::current_timestamp();
        let (issued_at, expires_at) = (now, now + 86_400);
        let payload = build_cert_sign_payload(
            device.label,
            "example.org",
            &identity_key,
            &device.id,
            issued_at,
            expires_at,
        );
        SenderCertificate {
            user_id: device.label.to_string(),
            domain: "example.org".to_string(),
            identity_key,
            device_id: device.id.clone(),
            issued_at,
            expires_at,
            signature: self.key.sign(&payload).to_bytes().to_vec(),
            server_kid: Vec::new(),
            server_signature_hybrid: Vec::new(),
        }
    }

    /// Доставить всё, что лежит для `device`. Каждое письмо становится событием
    /// `MessageReceived`, и ядро отвечает действиями, которые тут же исполняются.
    fn deliver_to(&mut self, device: &mut Device) {
        // `std::mem::take` забирает вектор, оставляя на его месте пустой: так можно итерировать
        // по письмам и одновременно пользоваться `self` (класть новые письма в `mailbox`).
        let mail = std::mem::take(&mut self.mailbox);
        let (mine, others): (Vec<_>, Vec<_>) = mail.into_iter().partition(|d| d.to == device.id);
        self.mailbox = others;

        for d in mine {
            println!(
                "\n  [server] → {}: сообщение {} от {} ({} байт)",
                device.label,
                d.message_id,
                short(&d.from),
                d.payload.len()
            );
            let actions = device.core.handle_event(IncomingEvent::MessageReceived {
                message_id: d.message_id,
                from: d.from,
                data: d.payload,
                content_type: d.content_type,
                sender_certificate: Some(Box::new(d.certificate)),
                envelope_session: None,
            });
            execute(device, self, actions);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Исполнитель действий — «главный цикл» приложения
// ─────────────────────────────────────────────────────────────────────────────

/// Исполнить список действий для `device`. Это то, что в iOS делает Swift после каждого
/// `handleEvent`: пройти по списку и сделать каждое. Некоторые действия порождают новые события
/// (нужен бандл → сходили на сервер → `SessionBundleFetched`), и тогда исполнитель вызывает
/// ядро снова и исполняет его ответ — отсюда рекурсия.
///
/// `match` здесь исчерпывающий: если в ядре появится новый вариант `Action`, этот файл
/// перестанет компилироваться — ровно так клиент узнаёт, что должен научиться чему-то новому.
fn execute(device: &mut Device, server: &mut Server, actions: Vec<Action>) {
    for action in actions {
        match action {
            Action::SaveToSecureStore { slot, data } => {
                // `data` — `SecretBytes`: обнуляется при освобождении и не печатается в Debug.
                let bytes = data.expose().to_vec();
                println!(
                    "    {} ⟶ Keychain[{slot:?}] = {} байт",
                    device.label,
                    bytes.len()
                );
                device.secure_store.insert(format!("{slot:?}"), bytes);
            }
            Action::SendEncryptedMessage {
                to,
                payload,
                message_id,
                content_type,
            } => {
                println!(
                    "    {} ⟶ сервер: {message_id} для {} ({} байт шифротекста, тип {content_type})",
                    device.label,
                    short(&to),
                    payload.len()
                );
                let certificate = server.certify(device);
                server.mailbox.push(Delivery {
                    to,
                    from: device.id.clone(),
                    message_id,
                    content_type,
                    payload,
                    certificate,
                });
            }
            Action::OpenSession { contact_id } => {
                // Сессии с этим контактом нет: ядро просит бандл. Приложение идёт на сервер и
                // отвечает событием `SessionBundleFetched` — с бандлом или с ошибкой.
                println!(
                    "    {} ⟶ сервер: дай бандл {}",
                    device.label,
                    short(&contact_id)
                );
                let bundle = server.fetch_bundle(&contact_id);
                let next = device
                    .core
                    .handle_event(IncomingEvent::SessionBundleFetched {
                        contact_id,
                        bundle: Box::new(bundle),
                    });
                execute(device, server, next);
            }
            Action::MessageQueuedPendingInit {
                contact_id,
                queued_count,
            } => {
                println!(
                    "    {}: сообщение для {} ждёт сессии (в очереди {queued_count})",
                    device.label,
                    short(&contact_id)
                );
            }
            Action::OpenReceiving { contact_id } => {
                // Пришло первое сообщение от устройства, с которым сессии нет. Ядро не открывает
                // её внутри `handle_event`, а просит отдельный вызов: приложение сначала
                // убеждается, что сертификат отправителя проверяем (ключ сервера есть).
                println!(
                    "    {}: первое сообщение от {} — открываю сессию на приёме",
                    device.label,
                    short(&contact_id)
                );
                let opened = device.core.open_receiving(&contact_id);
                println!(
                    "      открыто с {:?}, от сообщения {:?}",
                    opened.opened_device.as_deref().map(short),
                    opened.opener_message_id
                );
                execute(device, server, opened.actions);
            }
            Action::MessageDecrypted {
                contact_id,
                message_id,
                plaintext,
            } => {
                println!(
                    "    {} ✉ от {} [{message_id}]: {:?}",
                    device.label,
                    short(&contact_id),
                    String::from_utf8_lossy(&plaintext)
                );
            }
            Action::NotifyNewMessage { chat_id, preview } => {
                println!(
                    "    {} 🔔 чат {}: {preview:?}",
                    device.label,
                    short(&chat_id)
                );
            }
            Action::NotifySessionCreated { contact_id } => {
                println!(
                    "    {} ✓ сессия с {} установлена",
                    device.label,
                    short(&contact_id)
                );
            }
            Action::PersistAck {
                message_id,
                timestamp: _,
            } => {
                device.ack_db.push(message_id);
            }
            Action::MarkMessageDelivered { message_id } => {
                println!("    {}: {message_id} доставлено", device.label);
            }
            Action::ScheduleTimer { timer_id, delay_ms } => {
                // Таймеры мы не крутим: пример синхронный. В приложении таймер сработает и
                // вернётся событием `TimerFired { timer_id }`.
                println!(
                    "    {}: таймер {timer_id:?} через {delay_ms} мс (здесь не исполняется)",
                    device.label
                );
            }
            Action::NotifyError { code, message } => {
                println!("    {} ✗ {code}: {message}", device.label);
            }
            // Остальные действия в этом сценарии не возникают; печатаем, если вдруг.
            other @ (Action::CallSignalDecrypted { .. }
            | Action::ControlFrameDecrypted { .. }
            | Action::PruneAckStore { .. }
            | Action::DuplicateDropped { .. }
            | Action::MalformedDropped { .. }
            | Action::SendDecryptionError { .. }
            | Action::SessionRetired { .. }
            | Action::ResendMessage { .. }
            | Action::CheckAckInDb { .. }) => {
                println!("    {}: {other:?}", device.label);
            }
        }
    }
}

/// Отправить текст: то, что делает приложение по нажатию «отправить».
///
/// Два шага, и первый — не ядра. Ядро шифрует только в существующую сессию; открыть её на
/// стороне отправителя — работа приложения: спросить у ядра, есть ли сессия, если нет —
/// сходить на сервер за бандлом получателя и отдать его в `init_session_with_bundle`. Так
/// устроен iOS `SessionInitializationService.initializeSession`. (Действие `OpenSession` ядро
/// выдаёт само только когда *оно* хочет переоткрыть сессию — при апгрейде до PQXDH v2.)
fn send(device: &mut Device, server: &mut Server, to: &str, message_id: &str, text: &str) {
    println!(
        "\n[{}] отправляет {} ⟶ {}: {text:?}",
        device.label,
        message_id,
        short(to)
    );
    if !device.core.has_session_for_sending(to) {
        println!(
            "    {}: сессии с {} нет — беру бандл у сервера",
            device.label,
            short(to)
        );
        let bundle = server.fetch_bundle(to).expect("peer is registered");
        // PQXDH v2: X3DH на X25519 плюс ML-KEM-1024 к Kyber SPK получателя (и к одноразовому,
        // если сервер его выдал). Результат — корневой ключ двойного храповика. Сессия есть
        // только у Алисы; Боб узнает о ней из заголовка первого сообщения.
        let session_id = device
            .core
            .init_session_with_bundle(to, bundle.x3dh, bundle.kyber, false)
            .expect("session init");
        println!(
            "    {}: сессия {} открыта как INITIATOR",
            device.label,
            short(&session_id)
        );
    }
    let actions = device.core.handle_event(IncomingEvent::OutgoingMessage {
        contact_id: to.to_string(),
        message_id: message_id.to_string(),
        plaintext: text.as_bytes().to_vec(),
        content_type: 0,
    });
    execute(device, server, actions);
}

/// Первые 8 символов id — для печати.
fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Сценарий
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    println!("== Регистрация ==");
    let mut server = Server::new();
    let mut alice = Device::new("alice");
    let mut bob = Device::new("bob");
    println!("  alice = {}  bob = {}", short(&alice.id), short(&bob.id));
    server.register(&mut alice);
    server.register(&mut bob);
    // Без этого Боб не откроет сессию от первого сообщения Алисы: сертификат отправителя
    // некому проверить.
    alice
        .core
        .set_trusted_server_keys(vec![server.verifying_key()]);
    bob.core
        .set_trusted_server_keys(vec![server.verifying_key()]);

    println!("\n== Первое сообщение: сессии ещё нет ==");
    let bob_id = bob.id.clone();
    let alice_id = alice.id.clone();
    send(&mut alice, &mut server, &bob_id, "m1", "Привет, Боб");
    server.deliver_to(&mut bob);

    println!("\n== Ответ: сессия уже есть, бандл не нужен ==");
    send(&mut bob, &mut server, &alice_id, "m2", "Привет, Алиса");
    server.deliver_to(&mut alice);

    println!("\n== Ещё два сообщения подряд ==");
    send(&mut alice, &mut server, &bob_id, "m3", "Как дела?");
    send(&mut alice, &mut server, &bob_id, "m4", "Ты тут?");
    server.deliver_to(&mut bob);

    println!("\n== Что осталось у каждого ==");
    for device in [&alice, &bob] {
        let peer = if device.id == alice_id {
            &bob_id
        } else {
            &alice_id
        };
        let health = device
            .core
            .get_session_health(peer)
            .expect("session exists");
        println!(
            "  {}: отправлено в текущей цепочке {}, получено {}, PQ: {:?} / {:?}; Keychain: {} слотов, ACK: {}",
            device.label,
            health.messages_sent,
            health.messages_received,
            health.pq_handshake,
            health.pq_authentication,
            device.secure_store.len(),
            device.ack_db.len()
        );
    }
    println!(
        "  сервер: {} писем в очереди, ни одного ключа",
        server.mailbox.len()
    );
}
