import { motion } from 'framer-motion';
import { SectionWrapper } from './SectionWrapper';
import { TerminalWindow } from './TerminalWindow';

const fileTree = `sniffguard v2/
│
├── 📄 sniffguard.py          # Main entry point
│
├── 📁 core/                  # Core scanning engine
│   ├── comprehensive_scanner.py
│   ├── advanced_detection.py
│   ├── monitor_mode.py
│   ├── realtime_monitor.py
│   ├── deauth_attack.py
│   ├── interface_detect.py
│   └── OS_detect.py
│
├── 📁 gui/                   # PyQt6 interface
│   └── main_window.py
│
├── 📁 threads/               # Background workers
│   └── deauth_thread.py
│
├── 📁 utils/                 # Helpers
│   ├── logger.py
│   ├── config.py
│   └── vendor_lookup.py
│
├── 📁 logs/                  # Auto-generated logs
├── 📄 requirements.txt
└── 📄 sniffguard.spec`;

const components = [
  { color: 'text-primary', title: 'Core Engine', desc: 'Scapy-based packet capture. Channel hopping. Beacon frame parsing. Hidden SSID probing. Deauth detection.' },
  { color: 'text-accent', title: 'GUI Layer', desc: 'PyQt6-based interface. Real-time table updates. Sortable columns. Export dialogs.' },
  { color: 'text-success', title: 'Thread Workers', desc: 'Background threads keep the UI responsive during heavy scanning operations.' },
  { color: 'text-warning', title: 'Utilities', desc: 'Vendor lookup database (OUI). Structured logger. Configuration management.' },
];

export function ArchitectureSection() {
  return (
    <SectionWrapper id="architecture" className="py-24">
      <div className="container">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            🏗️ Project Architecture
          </h2>
        </div>

        <div className="max-w-3xl mx-auto mb-12">
          <TerminalWindow title="file structure">
            <pre className="text-muted-foreground text-xs leading-relaxed whitespace-pre">{fileTree}</pre>
          </TerminalWindow>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-3xl mx-auto">
          {components.map((c, i) => (
            <motion.div
              key={c.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              whileHover={{ y: -4 }}
              className="glass-card p-5"
            >
              <div className={`w-3 h-3 rounded-full mb-3 ${c.color === 'text-primary' ? 'bg-primary' : c.color === 'text-accent' ? 'bg-accent' : c.color === 'text-success' ? 'bg-success' : 'bg-warning'}`} />
              <h3 className="font-display font-bold text-foreground mb-2">{c.title}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{c.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </SectionWrapper>
  );
}
