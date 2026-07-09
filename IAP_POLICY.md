# MATSU 인앱결제(IAP) 정책 대응 설계

## 핵심 원칙 (애플·구글 심사)
앱스토어/플레이스토어는 **"디지털 재화·구독"은 반드시 자사 인앱결제(IAP)** 로 팔라고 요구해요.
외부 PG(토스 등)로 디지털 재화를 팔면 **리젝/삭제 사유**가 됩니다. 반대로 **실물·실세계 서비스**는 외부 PG 허용.

## MATSU 결제 2-트랙 (권장 구조)
| 항목 | 성격 | 결제 수단 | 이유 |
|---|---|---|---|
| **M캐쉬 충전, 프리미엄 구독, 개인리그 참가(디지털 권한)** | 디지털 재화 | **IAP (애플/구글)** | 스토어 정책상 필수 |
| **코트비·게스트비 정산, 대회 상금, 심판비** | 실세계 서비스 | **외부 PG(토스)** | 실물/오프라인 서비스는 외부 결제 허용 |

> 즉, 앞서 만든 토스 결제는 **코트비·게스트비 정산** 쪽으로 쓰고,
> **M캐쉬·프리미엄**은 **IAP**로 파는 게 안전합니다. (웹 버전은 토스로 M캐쉬 판매 가능 — 웹은 스토어 정책 밖)

## 상품 ID (스토어 등록)
스토어 콘솔에 아래 소모성 상품(consumable)을 등록하고, 서버 `IAP_CASH` 맵과 일치시키세요.
```
matsu_cash_25   → 25 M캐쉬
matsu_cash_45   → 45
matsu_cash_90   → 90
matsu_cash_200  → 200
matsu_cash_600  → 600
matsu_cash_1100 → 1100
```
프리미엄은 **구독 상품**(auto-renewable)으로 별도 등록: `matsu_premium_monthly` 등.

## 흐름 (서버 검증 = 이미 구현됨)
1. 앱에서 `react-native-iap`로 상품 구매 → **영수증(receipt)/purchaseToken** 획득
2. 앱이 서버로 전송:
   - iOS: `POST /iap/apple { receipt }`  → 서버가 Apple `verifyReceipt`로 검증(prod→sandbox 폴백) → `IAP_CASH[product_id]` 지급
   - Android: `POST /iap/google { productId, purchaseToken }` → (서비스계정으로 Android Publisher API 검증 후 지급 — TODO 자리 표시)
3. 서버가 **중복 지급 방지**(transaction_id/purchaseToken 저장) 후 M캐쉬 적립 → 앱은 `finishTransaction`

## 서버 env
```
APPLE_IAP_SHARED_SECRET=   # App Store Connect > 앱 > App 정보 > 공유 비밀키
GOOGLE_SA_EMAIL=           # 구글 서비스계정 (Android Publisher API 권한)
```

## 앱(react-native-iap) 스케치
```js
import * as IAP from 'react-native-iap';
const SKUS = ['matsu_cash_25','matsu_cash_45','matsu_cash_90','matsu_cash_200','matsu_cash_600','matsu_cash_1100'];
await IAP.initConnection();
const products = await IAP.getProducts({ skus: SKUS });
await IAP.requestPurchase({ sku: 'matsu_cash_200' });
// purchaseUpdatedListener 에서:
//  iOS: purchase.transactionReceipt → POST /iap/apple
//  Android: purchase.purchaseToken + productId → POST /iap/google
//  서버 200이면 IAP.finishTransaction({ purchase, isConsumable:true })
```

## 체크리스트
- [ ] 스토어 콘솔에 상품 등록 (ID 일치)
- [ ] 서버 `IAP_CASH` 맵/구독 상품 반영
- [ ] `APPLE_IAP_SHARED_SECRET`, 구글 서비스계정 설정
- [ ] 중복 지급 방지 테이블 추가
- [ ] 심사 시 "디지털 재화=IAP, 실세계=PG" 분리 명확화
- [ ] 세금계산서·전자금융 등 국내 규제는 전문가 확인
