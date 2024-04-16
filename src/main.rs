use cryptoki::{
    context::{CInitializeArgs, Function, Pkcs11},
    object::{self, Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::UserType,
    slot,
};
use dotenv::dotenv;
use secrecy::{ExposeSecret, Secret};
use std::fmt::{self, Debug, DebugList};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    // PKCS#11 라이브러리 경로
    let lib_path =
        std::env::var("CRYPTOKI_PATH").expect("CRYPTOKI_PATH 환경 변수를 설정해야 합니다.");

    // PKCS#11 라이브러리 인스턴스를 생성.
    let pkcs11 = Pkcs11::new(lib_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // 사용 가능한 슬롯을 검색
    let slots = pkcs11.get_all_slots()?;

    let slot = slots.get(0).ok_or("No available slots")?;
    let session = pkcs11.open_rw_session(*slot)?;

    // 사용자 PIN으로 토큰에 로그인
    let user_pin = Secret::new(
        std::env::var("USER_PASSWORD")
            .expect("USER PIN을 확인하세요.")
            .to_owned(),
    );
    session.login(UserType::User, Some(&user_pin))?;

    // SLOT 및 TOKEN (HSM 및 Partition) 정보 확인
    let slot_info = pkcs11.get_slot_info(*slot);
    let token_info = pkcs11.get_token_info(*slot);
    let slot_event = pkcs11.get_slot_event();
    let is_support = pkcs11.is_fn_supported(Function::FindObjects);
    println!("Slot Info : {:#?}", slot_info);
    println!("Token Info : {:#?}", token_info);
    println!("Slot Event : {:#?}", slot_event);
    println!("Is Support : {:#?}", is_support);

    // Handle Key LABEL 탐색 테스트
    let template = [Attribute::Label(
        String::from("Generated RSA Public Key").into_bytes(),
    )];

    println!("{:#?}", session.get_session_info());
    println!("{:#?}", session.find_objects(&template));

    session.close();
    Ok(())
}
