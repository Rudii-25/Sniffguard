import { motion } from 'framer-motion';
import { SectionWrapper } from './SectionWrapper';
import { Lightbulb } from 'lucide-react';

const usageSteps = [
  { num: 1, title: 'Interface Selection', desc: 'Launch the tool. Click "Detect Interfaces". Your wireless cards (e.g., wlan0, wlan1) will appear in a dropdown. Select the one you want to use.' },
  { num: 2, title: 'Start Scanning', desc: 'Click "Start Scan". SniffGu@rd puts your card into Monitor Mode and begins hopping through channels to discover all nearby access points.' },
  { num: 3, title: 'Read the Dashboard', desc: 'The main table shows SSID, BSSID, PWR (signal strength), CH (channel), ENC (encryption type), and VENDOR (manufacturer from OUI lookup).' },
  { num: 4, title: 'Export & Analyze', desc: 'Use File → Export to save results as CSV or JSON. Review detailed logs in the logs/ directory.' },
];

const mockData = [
  { ssid: 'HomeNetwork_5G', bssid: 'AA:BB:CC:DD:EE:FF', pwr: '-42', ch: '36', enc: 'WPA2', vendor: 'TP-Link', encColor: 'text-success' },
  { ssid: 'OFFICE_WIFI', bssid: '11:22:33:44:55:66', pwr: '-61', ch: '6', enc: 'WPA3', encColor: 'text-success', vendor: 'Cisco Systems' },
  { ssid: '[Hidden SSID]', bssid: '77:88:99:AA:BB:CC', pwr: '-75', ch: '11', enc: 'WEP', encColor: 'text-danger', vendor: 'D-Link' },
  { ssid: 'FreeWifi', bssid: 'DD:EE:FF:00:11:22', pwr: '-80', ch: '1', enc: 'OPEN', encColor: 'text-danger', vendor: 'Netgear' },
];

export function UsageSection() {
  return (
    <SectionWrapper id="usage" className="py-20">
      <div className="container">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            📖 How to Use SniffGu@rd
          </h2>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
          {/* Steps */}
          <div className="space-y-6">
            {usageSteps.map((s, i) => (
              <motion.div
                key={s.num}
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="flex gap-4"
              >
                <div className="w-8 h-8 rounded-full bg-gradient-accent flex items-center justify-center text-primary-foreground font-bold text-sm flex-shrink-0 mt-1">
                  {s.num}
                </div>
                <div>
                  <h3 className="font-display font-bold text-foreground mb-1">{s.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">{s.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>

          {/* GUI Mock */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="terminal-window overflow-hidden"
          >
            {/* Title bar */}
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
              <div className="w-3 h-3 rounded-full bg-danger" />
              <div className="w-3 h-3 rounded-full bg-warning" />
              <div className="w-3 h-3 rounded-full bg-success" />
              <span className="text-xs font-mono text-muted-foreground ml-2">🛡️ SniffGu@rd V2.0</span>
            </div>

            {/* Toolbar */}
            <div className="flex gap-2 px-4 py-2 border-b border-border">
              {['Detect Interfaces', 'Start Scan', 'Stop Scan', 'Export'].map((btn) => (
                <span key={btn} className="text-[10px] font-mono px-2 py-1 rounded bg-surface-2 text-muted-foreground border border-border">
                  {btn}
                </span>
              ))}
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    {['SSID', 'BSSID', 'PWR', 'CH', 'ENC', 'VENDOR'].map((h) => (
                      <th key={h} className="text-left px-3 py-2 font-semibold">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {mockData.map((row, i) => (
                    <motion.tr
                      key={row.bssid}
                      initial={{ opacity: 0 }}
                      whileInView={{ opacity: 1 }}
                      viewport={{ once: true }}
                      transition={{ delay: 0.5 + i * 0.15 }}
                      className="border-b border-border/50 hover:bg-surface-2/50"
                    >
                      <td className="px-3 py-2 text-foreground">{row.ssid}</td>
                      <td className="px-3 py-2 text-muted-foreground">{row.bssid}</td>
                      <td className="px-3 py-2 text-foreground">{row.pwr}</td>
                      <td className="px-3 py-2 text-foreground">{row.ch}</td>
                      <td className={`px-3 py-2 font-semibold ${row.encColor}`}>{row.enc}</td>
                      <td className="px-3 py-2 text-muted-foreground">{row.vendor}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Status bar */}
            <div className="px-4 py-2 border-t border-border flex items-center gap-4 text-[10px] font-mono text-muted-foreground">
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                Scanning...
              </span>
              <span>4 networks found</span>
              <span>Channel: 6</span>
            </div>
          </motion.div>
        </div>

        {/* Pro Tip */}
        <div className="mt-8 border-l-4 border-primary bg-primary/5 p-4 rounded-r-lg flex items-start gap-3">
          <Lightbulb size={20} className="text-primary flex-shrink-0 mt-0.5" />
          <p className="text-sm text-muted-foreground">
            <strong className="text-primary">Pro Tip:</strong> Use an external high-gain WiFi adapter like Alfa AWUS036ACH for significantly better range, sensitivity, and monitor mode support.
          </p>
        </div>
      </div>
    </SectionWrapper>
  );
}
