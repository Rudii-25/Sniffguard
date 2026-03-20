import { motion } from 'framer-motion';
import { SectionWrapper } from './SectionWrapper';

const stats = [
  { icon: '🔬', label: 'Scanning Modules', value: '7+' },
  { icon: '🌐', label: 'Protocols Supported', value: 'WEP · WPA · WPA2 · WPA3' },
  { icon: '📦', label: 'Python Dependencies', value: '4 Core Libraries' },
  { icon: '⚡', label: 'Scan Speed', value: 'Real-Time' },
];

export function StatsBar() {
  return (
    <SectionWrapper id="stats" className="py-8">
      <div className="container">
        <div className="glass rounded-xl px-6 py-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
            {stats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="text-center"
              >
                <div className="text-2xl mb-1">{stat.icon}</div>
                <div className="font-display font-bold text-foreground text-lg">{stat.value}</div>
                <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </SectionWrapper>
  );
}
