import { motion } from 'framer-motion';
import { SectionWrapper } from './SectionWrapper';

const steps = [
  { num: 1, icon: '🔌', title: 'Connect Your Adapter', desc: 'Plug in a supported wireless adapter (or use built-in wlan0). External high-gain adapters like Alfa Network give best results.' },
  { num: 2, icon: '🔍', title: 'Detect Interfaces', desc: 'Click "Detect Interfaces" in the GUI. SniffGu@rd scans your system for available wireless cards and lists them.' },
  { num: 3, icon: '📡', title: 'Start Scanning', desc: 'Select your interface and click "Start Scan". The tool switches to Monitor Mode and begins channel hopping to capture all beacon frames.' },
  { num: 4, icon: '📊', title: 'Analyze Results', desc: 'The dashboard populates in real-time with SSID, BSSID, signal strength, channel, encryption type, and vendor info. Export when done.' },
];

export function HowItWorksSection() {
  return (
    <SectionWrapper id="how-it-works" className="py-16">
      <div className="container">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            ⚙️ How It Works
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 relative">
          {/* Connecting line (desktop) */}
          <div className="hidden lg:block absolute top-12 left-[12%] right-[12%] h-px border-t border-dashed border-primary/30" />

          {steps.map((s, i) => (
            <motion.div
              key={s.num}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15 }}
              className="text-center relative"
            >
              <div className="w-12 h-12 rounded-full bg-gradient-accent flex items-center justify-center mx-auto mb-4 text-primary-foreground font-bold font-display text-lg relative z-10">
                {s.num}
              </div>
              <div className="text-3xl mb-3">{s.icon}</div>
              <h3 className="font-display font-bold text-foreground mb-2">{s.title}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">{s.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </SectionWrapper>
  );
}
