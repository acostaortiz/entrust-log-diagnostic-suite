/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - RECEPTOR SYSLOG Y MONITOREO EN TIEMPO REAL
   Modo SOC / NOC Preventivo (Opción D) — Captura UDP/TCP 514 / WebSocket Stream
   ========================================================================== */

class SyslogCollectorEngine {
  constructor() {
    this.isLive = false;
    this.timer = null;
    this.buffer = [];
    this.totalEvents = 0;
    this.criticalEvents = 0;
    this.ratePerSec = 0;
    this.lastTickTime = Date.now();
    this.tickCount = 0;
    this.audioCtx = null;
  }

  initAudio() {
    if (!this.audioCtx) {
      const AudioCtxClass = window.AudioContext || window.webkitAudioContext;
      if (AudioCtxClass) this.audioCtx = new AudioCtxClass();
    }
  }

  playAlertChime() {
    try {
      this.initAudio();
      if (!this.audioCtx) return;
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, this.audioCtx.currentTime); // Nota A5
      gain.gain.setValueAtTime(0.15, this.audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, this.audioCtx.currentTime + 0.3);
      osc.connect(gain);
      gain.connect(this.audioCtx.destination);
      osc.start();
      osc.stop(this.audioCtx.currentTime + 0.3);
    } catch(e) {}
  }

  startSimulation(onEventReceived) {
    if (this.isLive) return;
    this.isLive = true;
    this.initAudio();

    const nodes = ['SACVWIG01 (Canal Web)', 'SACVWIG02 (Canal Móvil)', 'SACVWIG03 (Canal Empresas)', 'SACVWIG04 (Gateway APIs)'];
    const codes = [
      { code: '5202000', msg: 'Authentication successful for user', level: 'INFO' },
      { code: '5202013', msg: 'Invalid user ID or password provided', level: 'ERROR' },
      { code: '5202404', msg: 'Database connection pool exhausted in identityguard.properties', level: 'CRITICAL' },
      { code: '5205150', msg: 'Authorization Failure: Client Secret Invalid for Pago Móvil API', level: 'CRITICAL' },
      { code: 'AUD106', msg: 'Entrust IdentityGuard Administration Service pulse check OK', level: 'INFO' },
      { code: 'AUD2300', msg: 'Soft token challenge processed successfully', level: 'INFO' }
    ];

    this.timer = setInterval(() => {
      if (!this.isLive) return;

      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      const sample = codes[Math.floor(Math.random() * codes.length)];
      const randomUser = `user_${Math.floor(Math.random() * 8999 + 1000)}`;

      const timeStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
      const rawLog = `[${timeStr}] [${randomNode}] [${sample.level}] [IG.SYSTEM] [${sample.code}] ${sample.msg} (User: ${randomUser})`;

      const parsed = {
        id: `syslog-live-${Date.now()}-${Math.random()}`,
        timestamp: timeStr,
        node: randomNode,
        level: sample.level,
        code: sample.code,
        message: rawLog,
        user: randomUser,
        diagnostic: window.knowledgeBaseEngine ? window.knowledgeBaseEngine.diagnoseLogWithCli(rawLog) : null
      };

      this.totalEvents++;
      this.tickCount++;
      if (sample.level === 'CRITICAL' || sample.level === 'ERROR') {
        this.criticalEvents++;
        this.playAlertChime();
      }

      const now = Date.now();
      if (now - this.lastTickTime >= 1000) {
        this.ratePerSec = this.tickCount;
        this.tickCount = 0;
        this.lastTickTime = now;
      }

      if (onEventReceived) onEventReceived(parsed, {
        total: this.totalEvents,
        critical: this.criticalEvents,
        rate: this.ratePerSec
      });
    }, 150);
  }

  stopStream() {
    this.isLive = false;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

window.syslogCollectorEngine = new SyslogCollectorEngine();
