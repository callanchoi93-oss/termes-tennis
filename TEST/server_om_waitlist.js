// ── 오픈매치 대기 명단 ─────────────────────────────────────────
// 구장 계약 전이라 매치가 하나도 없다. om_likes 는 매치별 관심이라 쓸 수 없어
// 서비스 오픈을 기다리는 사람을 따로 모은다.
db.exec(`CREATE TABLE IF NOT EXISTS om_waitlist (
  user_id INTEGER PRIMARY KEY,
  region TEXT, sport TEXT, created_at BIGINT
);`);

const OM_GOAL = 50;   // 이만큼 모이면 첫 코트를 연다 (앱의 OM_GOAL 과 같은 값)

function omWaitPayload(uid) {
  const count = db.prepare('SELECT COUNT(*) c FROM om_waitlist').get().c;
  const mine  = !!db.prepare('SELECT 1 FROM om_waitlist WHERE user_id=?').get(uid);
  // 얼굴 몇 개 — 사진이 없으면 앱이 색 원으로 그린다
  const faces = db.prepare(`SELECT u.photo FROM om_waitlist w JOIN users u ON u.id=w.user_id
                            ORDER BY w.created_at DESC LIMIT 4`).all()
    .map(r => ({ photo: r.photo || null }));
  return { count, mine, goal: OM_GOAL, faces };
}

app.get('/om/waitlist', auth, (req, res) => res.json(omWaitPayload(req.uid)));

app.post('/om/waitlist', auth, (req, res) => {
  const { region, sport } = req.body || {};
  db.prepare(`INSERT INTO om_waitlist (user_id,region,sport,created_at) VALUES (?,?,?,?)
              ON CONFLICT(user_id) DO UPDATE SET region=excluded.region, sport=excluded.sport`)
    .run(req.uid, String(region || '전국'), String(sport || 'tennis'), now());
  res.json(omWaitPayload(req.uid));
});
