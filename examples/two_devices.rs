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
//! Сценарии, по порядку в `main`:
//!
//! 1. Регистрация и первая переписка: сессия открывается у отправителя из бандла получателя,
//!    у получателя — из заголовка первого сообщения.
//! 2. Перезапуск: устройство «умирает» (ядро уничтожается) и поднимается заново из того, что
//!    приложение успело сохранить, — и переписка продолжается с того же места.
//! 3. Повторная доставка: сервер приносит уже прочитанное сообщение дважды — до перезапуска
//!    его узнаёт ACK-кэш в памяти, после перезапуска ядро спрашивает базу ACK приложения.
//! 4. Потерянное состояние оркестратора: ключи и запись сессии на месте, а сессия всё равно не
//!    восстанавливается — и почему.
//! 5. Опоздавшее сообщение: одно письмо застряло в пути, следующие пришли раньше — внутри одной
//!    цепочки храповика и через DH-поворот. Что ядро откладывает, чтобы прочитать его потом, и
//!    где предел.
//!
//! Читать сверху вниз: `Device` (устройство: ядро + его «Keychain»), `Server` (хранит бандлы
//! ключей, подписывает сертификаты отправителя, носит почту), `execute` (исполнитель действий —
//! то, чем в реальном приложении является главный цикл), `main` (сценарии).

use std::collections::HashMap;

use construct_core::crypto::client_api::ClassicClient;
use construct_core::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use construct_core::crypto::sealed_sender::{SenderCertificate, build_cert_sign_payload};
use construct_core::crypto::suites::classic::ClassicSuiteProvider;
use construct_core::orchestration::orchestrator::{KyberBundleKeys, Orchestrator, SessionBundle};
use construct_core::orchestration::{Action, IncomingEvent, SecureStoreSlot};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rand::rngs::OsRng;

// ─────────────────────────────────────────────────────────────────────────────
// Устройство
// ─────────────────────────────────────────────────────────────────────────────

/// Что приложение хранит в Keychain, по слотам.
///
/// Два слота ядро называет само (`SecureStoreSlot` в действии `SaveToSecureStore`); ещё два —
/// ключи и Kyber-преключи — приложение сохраняет по своей инициативе, вызывая экспорт. В iOS
/// это четыре разных записи Keychain с разными политиками доступа.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Slot {
    /// Identity, signing и SPK вместе с гибридным ключом подписи: `export_private_keys_cfe`.
    PrivateKeys,
    /// ML-KEM-1024 преключи с приватными половинами: `export_kyber_prekeys_cfe`.
    KyberPrekeys,
    /// Координационное состояние: ACK-кэш, блокировки открытия, эпохи SPK контактов.
    OrchestratorState,
    /// Запись сессии с одним контактом: текущее состояние храповика и предыдущие.
    Session(String),
}

impl From<SecureStoreSlot> for Slot {
    fn from(slot: SecureStoreSlot) -> Self {
        match slot {
            SecureStoreSlot::OrchestratorState => Slot::OrchestratorState,
            SecureStoreSlot::Session { contact_id } => Slot::Session(contact_id),
        }
    }
}

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
    /// «Keychain».
    secure_store: HashMap<Slot, Vec<u8>>,
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

        let mut device = Self {
            label,
            id,
            core,
            secure_store: HashMap::new(),
            ack_db: Vec::new(),
        };
        device.persist_keys();
        device
    }

    /// Сохранить ключи — то, о чём ядро *не* просит действием, а приложение делает само после
    /// регистрации и после каждой ротации. Потерять этот слот — потерять устройство.
    fn persist_keys(&mut self) {
        let keys = self.core.export_private_keys_cfe().expect("export keys");
        let kyber = self
            .core
            .export_kyber_prekeys_cfe()
            .expect("export kyber prekeys");
        println!(
            "    {} ⟶ Keychain[PrivateKeys] = {} байт, Keychain[KyberPrekeys] = {} байт",
            self.label,
            keys.len(),
            kyber.len()
        );
        self.secure_store.insert(Slot::PrivateKeys, keys);
        self.secure_store.insert(Slot::KyberPrekeys, kyber);
    }

    /// Перезапуск: процесс умер, ядро с ним; в живых — только Keychain и база ACK.
    ///
    /// `self` берётся по значению: старое ядро уничтожается здесь, и вернуть его нельзя —
    /// компилятор не даст пользоваться `bob` после `bob.restart(..)`. Это и есть смысл сцены.
    ///
    /// Порядок — тот же, что у iOS `CryptoManager.reloadCoreFromKeychain`: ключи, Kyber-преключи,
    /// состояние оркестратора, затем сессии (iOS поднимает их лениво, по первому обращению к
    /// контакту), затем событие `AppLaunched`. `with_orchestrator_state = false` моделирует
    /// запуск, при котором этот слот не прочитался; сценарий 4 показывает, чем это кончается.
    fn restart(self, server: &mut Server, with_orchestrator_state: bool) -> Self {
        let Device {
            label,
            id,
            core: old_core,
            secure_store,
            ack_db,
        } = self;
        drop(old_core); // процесс умер
        println!(
            "\n[{label}] перезапуск (слотов в Keychain: {})",
            secure_store.len()
        );

        let keys = secure_store
            .get(&Slot::PrivateKeys)
            .expect("no keys: this device is gone for good");
        let record = construct_core::cfe::decode_as::<construct_core::cfe::CfePrivateKeysV1>(
            keys,
            construct_core::cfe::CfeMessageType::PrivateKeys,
        )
        .expect("key record");
        let client =
            ClassicClient::<ClassicSuiteProvider>::from_private_keys_cfe(record).expect("keys");
        let mut core = Orchestrator::new(client, id.clone());
        println!(
            "    {label}: ключи восстановлены, id тот же: {}",
            short(&id)
        );

        if let Some(kyber) = secure_store.get(&Slot::KyberPrekeys) {
            core.import_kyber_prekeys_cfe(kyber).expect("kyber prekeys");
            println!(
                "    {label}: Kyber-преключи восстановлены ({} одноразовых осталось)",
                core.kyber_one_time_prekey_count()
            );
        }
        match secure_store.get(&Slot::OrchestratorState) {
            Some(state) if with_orchestrator_state => {
                core.import_orchestrator_state_cfe(state)
                    .expect("orchestrator state");
                println!("    {label}: состояние оркестратора восстановлено (ACK-кэш в памяти)");
            }
            _ => println!("    {label}: состояние оркестратора НЕ восстановлено — ACK-кэш пуст"),
        }
        let mut sessions = 0;
        for (slot, data) in &secure_store {
            if let Slot::Session(contact_id) = slot {
                // `match` на `Result`: обе ветки обязательны, и отказ ядра — тоже ответ.
                // Приложение в этом случае считает сессию отсутствующей: следующая отправка
                // откроет новую (так документирован `SESSION_PREDATES_ENVELOPE`).
                match core.import_session_cfe(contact_id, data) {
                    Ok(session_id) => {
                        sessions += 1;
                        println!(
                            "    {label}: сессия с {} восстановлена ({})",
                            short(contact_id),
                            short(&session_id)
                        );
                    }
                    Err(reason) => println!(
                        "    {label} ✗ сессия с {} НЕ восстановлена: {reason}",
                        short(contact_id)
                    ),
                }
            }
        }
        println!("    {label}: сессий восстановлено {sessions}");
        // Ключ сервера не хранится в ядре: приложение передаёт его при каждом запуске.
        core.set_trusted_server_keys(vec![server.verifying_key()]);

        let mut device = Self {
            label,
            id,
            core,
            secure_store,
            ack_db,
        };
        let actions = device.core.handle_event(IncomingEvent::AppLaunched);
        execute(&mut device, server, actions);
        device
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
#[derive(Clone)]
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
    /// Всё, что сервер когда-либо доставил: настоящий сервер хранит письмо, пока клиент не
    /// подтвердит получение, и после обрыва связи приносит его снова (сценарий 3).
    delivered: Vec<Delivery>,
    /// Письма, застрявшие в пути (сценарий 5): сервер их принял, но получателю отдаст позже
    /// тех, что пришли после.
    held: Vec<Delivery>,
}

impl Server {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self {
            key: SigningKey::from_bytes(&seed),
            registrations: HashMap::new(),
            mailbox: Vec::new(),
            delivered: Vec::new(),
            held: Vec::new(),
        }
    }

    /// Задержать письмо в пути. В жизни так выглядит обрыв соединения на одном из двух
    /// подключений, очередь на другом узле, доставка через push с опозданием — для ядра
    /// получателя всё это одно и то же: сообщение с номером N+1 пришло раньше N.
    fn hold(&mut self, message_id: &str) {
        let i = self
            .mailbox
            .iter()
            .position(|d| d.message_id == message_id)
            .expect("in mailbox");
        let d = self.mailbox.remove(i);
        println!("  [server] {} застряло в пути", d.message_id);
        self.held.push(d);
    }

    /// Вернуть застрявшее письмо в очередь доставки.
    fn release(&mut self, message_id: &str) {
        let i = self
            .held
            .iter()
            .position(|d| d.message_id == message_id)
            .expect("was held");
        let d = self.held.remove(i);
        println!("  [server] {} выбралось из пробки", d.message_id);
        self.mailbox.push(d);
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
        // Одноразовые ключи только что родились: их приватные половины надо сохранить до того,
        // как публичные уйдут на сервер, иначе после перезапуска ядро не сможет открыть сессию,
        // в которой отправитель воспользовался одним из них.
        device.persist_keys();

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
            self.delivered.push(d.clone());
            self.deliver_one(device, d);
        }
    }

    /// Принести ещё раз письмо, которое уже доставлялось: так ведёт себя сервер после обрыва
    /// связи, пока не получил подтверждения.
    fn redeliver(&mut self, device: &mut Device, message_id: &str) {
        let d = self
            .delivered
            .iter()
            .find(|d| d.message_id == message_id && d.to == device.id)
            .expect("was delivered before")
            .clone();
        self.deliver_one(device, d);
    }

    fn deliver_one(&mut self, device: &mut Device, d: Delivery) {
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
                let slot = Slot::from(slot);
                println!(
                    "    {} ⟶ Keychain[{}] = {} байт",
                    device.label,
                    slot_name(&slot),
                    bytes.len()
                );
                device.secure_store.insert(slot, bytes);
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
                // Ядро само хочет переоткрыть сессию (апгрейд до PQXDH v2). Приложение идёт на
                // сервер и отвечает событием `SessionBundleFetched` — с бандлом или с ошибкой.
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
                // Открытие на приёме сжигает одноразовый Kyber-преключ, если отправитель его
                // взял. Сожжённый ключ должен исчезнуть из Keychain до следующего запуска: иначе
                // после перезапуска он «воскреснет», а повторное использование одноразового
                // ключа — ровно то, чего он существует не допускать. В UDL это поле
                // `kyber_prekeys` в `ReceivingOpenResult`.
                if let Some(kyber) = device.core.take_kyber_prekeys_to_persist() {
                    println!(
                        "    {} ⟶ Keychain[KyberPrekeys] = {} байт (одноразовый ключ сожжён)",
                        device.label,
                        kyber.len()
                    );
                    device.secure_store.insert(Slot::KyberPrekeys, kyber);
                }
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
            Action::CheckAckInDb { message_id } => {
                // Кэш в памяти знает только то, что обработано в этом процессе. После перезапуска
                // ядро работает в режиме «каждый незнакомый id — вопрос к базе» (`AckStore`,
                // post-restart mode): база приложения — единственная память о прошлых запусках,
                // а расшифровывать дубликат нельзя — ключ сообщения уже потрачен.
                let is_processed = device.ack_db.contains(&message_id);
                println!(
                    "    {}: ядро спрашивает базу ACK про {message_id} — {}",
                    device.label,
                    if is_processed {
                        "уже было"
                    } else {
                        "новое"
                    }
                );
                let next = device.core.handle_event(IncomingEvent::AckDbResult {
                    message_id,
                    is_processed,
                });
                execute(device, server, next);
            }
            Action::DuplicateDropped { message_id } => {
                println!(
                    "    {}: {message_id} уже обработано — отброшено, пользователь не увидит",
                    device.label
                );
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
            // Остальные действия в этих сценариях не возникают; печатаем, если вдруг.
            other @ (Action::CallSignalDecrypted { .. }
            | Action::ControlFrameDecrypted { .. }
            | Action::PruneAckStore { .. }
            | Action::MalformedDropped { .. }
            | Action::SendDecryptionError { .. }
            | Action::SessionRetired { .. }
            | Action::ResendMessage { .. }) => {
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

fn slot_name(slot: &Slot) -> String {
    match slot {
        Slot::PrivateKeys => "PrivateKeys".to_string(),
        Slot::KyberPrekeys => "KyberPrekeys".to_string(),
        Slot::OrchestratorState => "OrchestratorState".to_string(),
        Slot::Session(contact_id) => format!("Session({})", short(contact_id)),
    }
}

fn health_line(device: &Device, peer: &str) {
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

/// Что храповик отложил «на потом»: ключи сообщений, которые ещё не пришли.
fn ratchet_line(device: &Device, peer: &str) {
    let health = device
        .core
        .get_session_health(peer)
        .expect("session exists");
    let stats = device.core.reorder_stats();
    println!(
        "  {}: получено в текущей цепочке {}, отложенных ключей {} (PQ: {}); с запуска расшифровано {}, самое глубокое опоздание {}",
        device.label,
        health.messages_received,
        health.skipped_keys_count,
        health.pq_skipped_keys_count,
        stats.decrypted,
        stats.max_skip_depth
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Сценарии
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    println!("==== 1. Регистрация и первая переписка ====");
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
    health_line(&alice, &bob_id);
    health_line(&bob, &alice_id);

    println!("\n\n==== 3а. Сервер приносит m4 ещё раз — до перезапуска ====");
    // Кэш в памяти помнит m4: ядро отбрасывает дубликат само, базу не спрашивает.
    server.redeliver(&mut bob, "m4");

    println!("\n\n==== 2. Перезапуск Боба ====");
    // Всё, что было в `bob.core`, сейчас исчезнет. Переменная `bob` после этой строки — уже
    // новое устройство, собранное из Keychain; к старому ядру доступа нет ни у кого.
    let mut bob = bob.restart(&mut server, true);

    println!("\n== Переписка продолжается с того же места ==");
    send(&mut alice, &mut server, &bob_id, "m5", "Ты перезапускался?");
    server.deliver_to(&mut bob);
    send(&mut bob, &mut server, &alice_id, "m6", "Да, и всё помню");
    server.deliver_to(&mut alice);
    health_line(&alice, &bob_id);
    health_line(&bob, &alice_id);

    println!("\n\n==== 3б. Сервер приносит m3 ещё раз — после перезапуска ====");
    // Кэш пуст: ядро спрашивает базу ACK, база помнит, дубликат отброшен.
    server.redeliver(&mut bob, "m3");

    println!("\n\n==== 4. Перезапуск без состояния оркестратора ====");
    // Ключи на месте, запись сессии на месте — а сессия не восстанавливается. В состоянии
    // оркестратора живёт envelope book: ключи, которыми запечатываются конверты sealed sender
    // этой сессии. Они выводятся из корня рукопожатия, который не хранится, поэтому запись
    // сессии без книги — состояние, на котором ничего нельзя ни запечатать, ни найти. Ядро
    // отказывает (`SESSION_PREDATES_ENVELOPE`), приложение считает сессию отсутствующей, и
    // следующая отправка откроет новую. Вывод: слот OrchestratorState так же важен, как ключи.
    let bob = bob.restart(&mut server, false);
    println!(
        "  bob: сессия с alice есть? {}",
        bob.core.has_active_session(&alice_id)
    );

    println!("\n== Keychain цел — обычный перезапуск возвращает всё ==");
    let mut bob = bob.restart(&mut server, true);
    send(&mut alice, &mut server, &bob_id, "m7", "Проверка связи");
    server.deliver_to(&mut bob);
    health_line(&bob, &alice_id);

    println!("\n\n==== 5а. Опоздавшее сообщение внутри одной цепочки ====");
    // Алиса шлёт три сообщения подряд; второе застревает. Боб получает m8 и сразу m10 — с
    // номером на единицу больше, чем ждал. Храповик не может ждать: ключ m10 выводится из
    // ключа цепочки через ключ m9, и ядро делает этот шаг, а ключ m9 *откладывает* — в
    // `skipped_message_keys` сессии, под номером цепочки и номером сообщения. Отложенный ключ
    // попадает в запись сессии, то есть в Keychain: в следующей записи Session видно, что она
    // подросла.
    send(&mut alice, &mut server, &bob_id, "m8", "Первое");
    send(&mut alice, &mut server, &bob_id, "m9", "Второе");
    send(&mut alice, &mut server, &bob_id, "m10", "Третье");
    server.hold("m9");
    server.deliver_to(&mut bob);
    ratchet_line(&bob, &alice_id);

    println!("\n== m9 добирается ==");
    // Ключ лежит ровно под тем номером, который сообщение называет в заголовке: m9 читается
    // без единого шага храповика, ключ после этого стирается — второй раз m9 не прочитать.
    server.release("m9");
    server.deliver_to(&mut bob);
    ratchet_line(&bob, &alice_id);

    println!("\n\n==== 5б. Опоздавшее сообщение через DH-поворот ====");
    // То же, но пока m12 стоит в пробке, стороны успевают обменяться репликами, и у Алисы
    // начинается новая цепочка (DH-поворот: ответ Боба несёт свежий ключ, Алиса отвечает на
    // него своим). К Бобу m14 приходит с незнакомым DH-ключом в заголовке и с pn — длиной
    // предыдущей цепочки Алисы. Боб видит, что из старой цепочки он прочёл меньше, чем pn,
    // откладывает недостающие ключи старой цепочки и только потом поворачивает храповик.
    send(&mut alice, &mut server, &bob_id, "m11", "Перед поворотом");
    send(&mut alice, &mut server, &bob_id, "m12", "Это застрянет");
    server.hold("m12");
    server.deliver_to(&mut bob);
    send(
        &mut bob,
        &mut server,
        &alice_id,
        "m13",
        "Получил только одно",
    );
    server.deliver_to(&mut alice);
    send(
        &mut alice,
        &mut server,
        &bob_id,
        "m14",
        "Уже на новой цепочке",
    );
    server.deliver_to(&mut bob);
    ratchet_line(&bob, &alice_id);

    println!("\n== m12 добирается — из цепочки, которой у Боба уже нет ==");
    // Заголовок m12 называет *старый* DH-ключ Алисы. Для храповика это выглядит как «нужен
    // поворот»: ключ не текущий. Поэтому отложенные ключи ищутся раньше любого шага (Signal
    // DR §3.5, TrySkippedMessageKeys). До 2026-10-20 порядок был обратный: ядро поворачивало
    // храповик «назад» от текущего корня, отложенный ключ всё равно читал m12, и испорченное
    // состояние сохранялось — следующее сообщение не расшифровывалось никогда (TODO 189 из
    // аудита ядра). Теперь m12 читается отложенным ключом, состояние не трогается, и m15
    // доказывает, что сессия жива.
    server.release("m12");
    server.deliver_to(&mut bob);
    send(&mut alice, &mut server, &bob_id, "m15", "Сессия цела?");
    server.deliver_to(&mut bob);
    ratchet_line(&bob, &alice_id);

    // Чего здесь не видно, потому что пример короткий. Отложенный ключ сообщения, которое не
    // придёт никогда, живёт в записи сессии семь дней (`max_skipped_message_age_seconds`) и
    // стирается при следующей расшифровке или импорте; теряется сообщение, не сессия. Два
    // предела защищают от злоумышленника, который присылает номер «миллион»: скачок больше
    // `max_message_jump` (2000) отвергается сразу, а когда отложенных ключей накопилось
    // `max_skipped_messages` (1000), следующее сообщение с пропуском не читается — «Too many
    // skipped messages». PQ-слой храповика откладывает ключи так же (`pq_skipped_keys_count`),
    // но хранит цепочки только двух последних эпох: сообщение старше теряется, и счётчик
    // `evicted_epoch_failures` в `reorder_stats` считает именно такие.
    println!(
        "\n  сервер: {} писем в очереди, {} доставлено, ни одного ключа",
        server.mailbox.len(),
        server.delivered.len()
    );
}
