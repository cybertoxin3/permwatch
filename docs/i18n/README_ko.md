<div align="center">

[Türkçe](README_tr.md) · [English](../../README.md) · [Русский](README_ru.md) · [Deutsch](README_de.md) · [Français](README_fr.md) · [Español](README_es.md) · [Português](README_pt.md) · [Italiano](README_it.md) · [Українська](README_uk.md) · [日本語](README_ja.md) · [简体中文](README_zh.md) · **한국어** · [العربية](README_ar.md)

<img src="../images/icon.png" width="128" alt="permwatch">

# permwatch

**Mac의 모든 앱이 무엇에 접근할 수 있는지 확인하세요.**

카메라, 마이크, 화면 기록, 로그인 항목.<br>
permwatch는 모든 권한 변경을 기록하고, 수상한 일이 생기면 바로 알려 줍니다.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)
![상태](https://img.shields.io/badge/%EC%83%81%ED%83%9C-%EA%B0%9C%EB%B0%9C%20%EC%A4%91-orange)

</div>

---

## 허용하고, 잊어버렸다

"화면 기록을 허용하십시오." "손쉬운 사용 접근 권한이 필요합니다." "로그인 시 열까요?"

우리는 하루에도 수십 번 "확인"을 누릅니다. 그런데 어떤 앱에 언제 어떤 권한을 줬는지 기억하시나요?
어떤 앱이 조용히 자신을 시동 항목에 추가했을까요? macOS는 그 답을 보여 주지 않습니다.

**permwatch는 보여 줍니다.**

<p align="center">
  <img src="../images/timeline_ko.png" alt="permwatch 타임라인" width="900">
</p>

## 시나리오

무료 PDF 변환기를 내려받습니다. 열어 보니 몇 가지 권한을 요청하고, "확인"을 누릅니다.
모든 것이 평범해 보입니다.

그동안 permwatch는 백그라운드에서 이런 일을 보고 있습니다.

| 시간 | 일어난 일 |
|---|---|
| 13:46 | 내려받은 앱의 **격리 플래그가 제거되어** Gatekeeper가 우회됨 |
| 13:47 | **서명 없는** 앱이 다운로드 폴더에서 처음 실행됨 |
| 13:48 | 1분 안에 **손쉬운 사용**과 **화면 기록** 권한을 모두 얻음 |
| 13:49 | **숨김 폴더의 프로그램을 시동 항목에 추가**함 |
| 03:12 | 한밤중, 당신이 자는 동안 **그 숨겨진 프로그램이 실행됨** |

하나씩 보면 모두 무해해 보이지만, 함께 보면 익숙한 공격 흐름입니다.
permwatch는 이 점들을 연결해 하나의 명확한 경고로 알려 줍니다.

<p align="center">
  <img src="../images/alert_ko.png" alt="permwatch 알림과 메뉴 막대" width="900">
</p>

## 기능

- 🕒 **타임라인:** 모든 권한 변경과 새 시동 항목을 날짜, 원인 프로세스와 함께 기록
- 🚨 **스마트 경고:** 서명 없는 앱, 심야 활동, Gatekeeper 우회 시도
- 🔍 **앱별 보기:** 앱이 가진 모든 권한을 카드 한 장으로
- 🧬 **서명 확인:** Apple인가요, 알려진 개발자인가요, 아니면 출처 불명인가요?
- 📍 **메뉴 막대에서:** 평소에는 조용히, 필요할 때는 확실하게

<p align="center">
  <img src="../images/apps_ko.png" alt="permwatch 앱 보기" width="900">
</p>

## 개인정보는 당신 곁에

permwatch는 **어떤 데이터도 외부로 보내지 않습니다.** 분석도, 계정도, 클라우드도 없습니다.
모든 기록은 당신의 Mac에만 남습니다. 개인정보 보호 도구라면 당연한 일이죠.

## 작동 방식

permwatch는 보안 소프트웨어를 위한 Apple의 공식 프레임워크인 **Endpoint Security**를 사용합니다.
핵심 엔진은 C로 작성되었습니다. 오직 **관찰만** 하며 시스템 동작에는 절대 개입하지 않습니다.

## 현재 상태

permwatch는 활발히 개발 중입니다.

- ✅ 이벤트를 수집하는 핵심 엔진(명령줄)
- ⏳ Apple Endpoint Security 권한: 신청 완료, 심사 중
- 🛠 macOS 앱과 인터페이스: 디자인 단계

> 위 이미지는 디자인 미리보기입니다. 시나리오의 "Konvertix"는 가상의 앱입니다.

개발자이고 핵심 엔진을 써 보고 싶다면: **[개발자 가이드(영어) →](../GELISTIRME_en.md)**

---

<div align="center">
<sub>macOS 보안에 호기심 많은 사람이, 같은 호기심을 가진 이들을 위해 만들었습니다.</sub>
</div>
