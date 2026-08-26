# 푸시 랜딩 고치기 · 서버 쪽

## 무엇이 끊어져 있었나

`sendPush()`는 링크를 계산해서 **알림함(notifications 표)에만** 넣습니다.
정작 폰으로 나가는 APNs 페이로드에는 `url: msg.url || '/'` 가 들어가는데,
`msg.url` 을 채워 보내는 곳이 한 군데도 없습니다. 그래서 항상 `'/'` 였고,
앱은 그 값을 보지도 않고 홈으로 보냈습니다. 양쪽 다 고쳐야 합니다.

앱 쪽은 `v1.1.2-0826c` 에 이미 들어갔습니다. 서버는 아래 한 줄이면 됩니다.

## 고칠 곳 — `sendPush()`

계산해 둔 `link` 를 폰으로 나가는 메시지에도 실어 줍니다.

```js
async function sendPush(userId, msg, opts) {
  const link = msg.link || ICON_LINKS[msg.icon] || null;
  if (!(opts && opts.skipInbox))
    db.prepare('INSERT INTO notifications (user_id,icon,title,sub,created_at,link) VALUES (?,?,?,?,?,?)')
      .run(userId, msg.icon || '🔔', msg.title || '', msg.body || '', now(), link);

  // ↓ 이 줄을 추가. 알림함에만 있던 링크를 폰 알림에도 함께 보낸다.
  const out = { ...msg, url: msg.url || link || 'home' };

  const rows = db.prepare('SELECT token, platform FROM devices WHERE user_id=?').all(userId);

  if (apnsReady()) {
    rows.filter(r => r.platform === 'ios').forEach(({ token }) => {
      apnsSend(token, out)          // ← msg 대신 out
        .then(r => { /* 그대로 */ }).catch(() => {});
    });
  }

  if (!webpush) return;
  for (const { token } of rows) {
    let sub;
    try { sub = JSON.parse(token); } catch { continue; }
    if (!sub || !sub.endpoint) continue;
    webpush.sendNotification(sub, JSON.stringify({
      title: out.title || 'MATSU', body: out.body || '', url: out.url,   // ← out.url
    })).catch(err => { /* 그대로 */ });
  }
}
```

`apnsSend()` 는 이미 `url: msg.url || '/'` 를 페이로드 루트에 넣고 있으므로
따로 손댈 필요가 없습니다.

## 앱이 아는 화면 이름

`ICON_LINKS` 가 내는 값과 앱의 화면 이름이 맞아야 합니다. 지금은 다 맞습니다.

| 값 | 가는 곳 |
|---|---|
| `home` | 홈 |
| `match` | 오픈매치 |
| `club` | 클럽 |
| `bracket` | 대진 |
| `league` | 리그 |
| `chat` | 채팅 |
| `sched` | 일정 |
| `me` | 내정보 |

앱은 이 목록에 없는 값이 오면 홈으로 보냅니다. 새 화면을 추가하실 때는
`index.html` 의 `pushNotificationActionPerformed` 안 `OK` 배열에도 이름을 넣어주세요.

## 더 정확하게 보내려면 (선택)

지금은 아이콘으로 화면을 짐작합니다. `📅` 는 모임 알림인데 `club` 으로 갑니다.
보내는 쪽에서 `link` 를 직접 주면 그 값이 우선합니다.

```js
sendPush(uid, { icon:'👋', title:'가입 신청이 왔어요',
                body:`${name} 님이 ${club} 가입을 신청했어요`,
                link:'club' });                       // ← 직접 지정
```

모임 알림은 일정 탭이 더 맞을 수 있습니다.

```js
sendPush(uid, { icon:'📅', title:'3일 뒤 모임 · 참석 체크하세요',
                body:'...', link:'sched' });
```

## 확인하는 법

1. 서버 배포 후 클럽 가입 신청을 하나 만들어 임원 폰으로 알림을 받습니다
2. 알림을 눌러 **클럽 탭**으로 들어가면 성공입니다
3. 안 되면 알림함(종 아이콘) 항목을 눌러보세요. 알림함은 예전부터 `link` 를 쓰고
   있어서 그쪽이 되면 서버 계산은 맞고 페이로드 전달만 빠진 것입니다

## 남은 한계

지금은 **화면까지만** 갑니다. "어느 클럽의 어느 신청"까지는 못 가요.
거기까지 하려면 `link` 를 `club:12` 처럼 보내고 앱에서 쪼개 열어야 하는데,
알림 종류가 70개가 넘어 한 번에 하기보다 자주 눌리는 것부터 붙이는 편이 낫습니다.
가입 신청·대진 발행·오픈매치 확정 셋이 후보입니다.
