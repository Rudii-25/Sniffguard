import { motion } from 'framer-motion';
import { SectionWrapper } from './SectionWrapper';

const features = [
  { icon: '📡', title: 'Real-Time Scanning', desc: 'Discover all nearby Wi-Fi access points live, with no refresh needed. Shows SSID, BSSID, signal strength, channel, and encryption type.' },
  { icon: '🔐', title: 'Security Classification', desc: 'Automatically tags and color-codes Open, WEP, WPA, WPA2, and WPA3 networks. Instantly identify threats.' },
  { icon: '📶', title: 'Dual-Band Support', desc: 'Full support for 2.4 GHz and 5 GHz networks with accurate channel resolution and band detection.' },
  { icon: '🏠', title: 'BSSID / OUI Lookup', desc: 'Identify the manufacturer of any access point directly from its MAC address using a built-in OUI vendor database.' },
  { icon: '📊', title: 'Signal Strength Mapping', desc: 'Visualize RSSI levels to physically locate access points. Find the exact position of a rogue AP.' },
  { icon: '🛡️', title: 'Security Alerts', desc: 'Instantly detect unsecured (Open) networks and weak WEP-encrypted networks with highlighted alerts.' },
  { icon: '🕵️', title: 'Hidden SSID Discovery', desc: "Specialized packet techniques to reveal hidden network names that don't broadcast their SSID." },
  { icon: '📁', title: 'Log Management', desc: 'Structured, timestamped logging stored in the logs/ directory. Export scan results as CSV or JSON.' },
  { icon: '🖥️', title: 'Professional PyQt6 GUI', desc: 'A clean, responsive PyQt6 graphical interface with real-time data tables, sortable columns, and live updates.' },
  { icon: '🔧', title: 'Monitor Mode Auto-Switch', desc: 'Automatically switches the selected wireless interface into monitor mode — no manual iwconfig needed.' },
  { icon: '💉', title: 'Packet Injection Support', desc: 'Advanced network testing capabilities via packet injection for authorized penetration testing.' },
  { icon: '📡', title: 'Deauth Detection', desc: 'Detect and log deauthentication attacks happening on your network in real time.' },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
};

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { type: 'spring' as const, duration: 0.4, bounce: 0.1 } },
};

export function FeaturesSection() {
  return (
    <SectionWrapper id="features" className="py-24">
      <div className="container">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            ⚡ Powerful Features
          </h2>
          <p className="text-muted-foreground text-lg max-w-xl mx-auto">
            Everything you need for professional wireless security auditing.
          </p>
        </div>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-100px" }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"
        >
          {features.map((f) => (
            <motion.div
              key={f.title}
              variants={item}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
              className="glass-card p-6 group cursor-default"
            >
              <div className="text-4xl mb-4">{f.icon}</div>
              <h3 className="font-display font-bold text-foreground text-lg mb-2">{f.title}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{f.desc}</p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </SectionWrapper>
  );
}
