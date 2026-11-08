<div align="center">

[Türkçe](README_tr.md) · [English](../../README.md) · [Русский](README_ru.md) · [Deutsch](README_de.md) · [Français](README_fr.md) · [Español](README_es.md) · [Português](README_pt.md) · [Italiano](README_it.md) · [Українська](README_uk.md) · [日本語](README_ja.md) · [简体中文](README_zh.md) · **한국어** · [العربية](README_ar.md)

<img src="../images/icon.png" width="128" alt="permwatch">

# permwatch

**Mac의 모든 앱이 무엇에 접근할 수 있는지 확인하세요.**

카메라, 마이크, 화면 기록, 로그인 항목.<br>
permwatch는 모든 권한 변경을 기록하고, 수상한 일이 생기면 바로 알려 줍니다.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-14%2B-black?logo=apple)
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

- 🛡 **개요와 원클릭 검사:** 실행하면 명확한 판정을 보여 줍니다. '내 Mac 검사'는 악성 코드 검사를 실행하고 브라우저 탈취, 트래픽 가로채기(루트 인증서, 프로파일, 프록시, DNS, VPN), VPN 누출, 원격 접근, 스파이웨어 특유의 권한 조합을 확인합니다. 모든 항목에 수정 버튼이 있습니다.
- 🐞 **악성 코드 검사:** 오픈 소스 YARA 엔진으로 앱, 로그인 항목, 실행 중인 프로그램, 다운로드를 **Apple의 XProtect 시그니처**와 대조합니다. 빠른 검사는 약 10초가 걸리며 새 다운로드는 자동으로 검사합니다.
- 🔐 **권한:** 모든 변경 기록, 삭제된 앱에 남은 권한, 원클릭 취소, 앱 제거.
- 🌐 **네트워크:** 어떤 앱이 어디에 연결하는지, 프로세스 이름과 쉬운 설명이 붙은 패킷 캡처, macOS 내장 방화벽으로 서버 차단.
- ⬇️ **다운로드, 🎙 마이크와 카메라, ⌨️ 터미널**(보안 명령 포함).

<p align="center">
  <img src="../images/apps_ko.png" alt="permwatch 앱 보기" width="900">
</p>

## 이것이 아닌 것

permwatch는 **완전한 백신이 아닙니다.** Apple 시그니처가 아는 악성 코드는 찾지만 프로그램을 실시간으로 차단하지는 않습니다. 규칙은 휴리스틱이라 오탐과 미탐이 있을 수 있습니다.

## 개인정보는 내 Mac에

permwatch는 **사용자에 관한 어떤 정보도 보내지 않습니다.** 분석, 계정, 클라우드가 없습니다. 자세히: **[PRIVACY.md](../../PRIVACY.md)**

## 작동 방식

- macOS 권한 데이터베이스와 로그인 항목을 (전체 디스크 접근 권한으로) 읽고 변경을 감시합니다.
- 선택 사항인 **관리자 모드**는 한 번 승인하면 시스템 서비스(SMAppService)로 설치되며 서명은 macOS가 확인합니다.
- 패킷 캡처는 libpcap과 Apple PKTAP(패킷별 프로세스)를 사용합니다.
- 실시간 이벤트용 Endpoint Security 엔진(C)이 준비되어 Apple의 승인을 기다리고 있습니다.

## 서드파티 코드

- [YARA](https://github.com/VirusTotal/yara) v4.5.8 (BSD-3-Clause)
- [SwiftTerm](https://github.com/migueldeicaza/SwiftTerm) v1.20.0 (MIT)

## 상태

- ✅ 13개 언어를 지원하는 macOS 앱, Apple 공증 완료.
- ⏳ Apple Endpoint Security 권한: 검토 중.

개발자이고 핵심 엔진을 써 보고 싶다면: **[개발자 가이드(영어) →](../GELISTIRME_en.md)**

---

<div align="center">
<sub>macOS 보안에 호기심 많은 사람이, 같은 호기심을 가진 이들을 위해 만들었습니다.</sub>
</div>
