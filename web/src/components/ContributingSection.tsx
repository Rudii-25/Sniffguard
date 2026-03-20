import { motion } from 'framer-motion';
import { SectionWrapper } from './SectionWrapper';
import { TerminalWindow } from './TerminalWindow';

const cards = [
  { icon: '🐛', title: 'Report Bugs', desc: 'Use the GitHub Issue Tracker at github.com/Rudii-25/Sniffguard/issues. Describe the bug clearly, provide reproduction steps, include your OS and WiFi adapter model.' },
  { icon: '💡', title: 'Request Features', desc: 'Open an issue labeled feature request at github.com/Rudii-25/Sniffguard/issues. Explain why it benefits the community and provide use case examples.' },
  { icon: '👩‍💻', title: 'Submit Pull Requests', desc: 'Fork → Branch → Code → Commit → PR on github.com/Rudii-25/Sniffguard. Follow the project code style and include tests where possible.' },
];

const prCode = `# Fork the repo on GitHub, then:
git checkout -b feature/YourFeatureName
git commit -m "feat: Add amazing new feature"
git push origin feature/YourFeatureName
# Open Pull Request on GitHub`;

export function ContributingSection() {
  return (
    <SectionWrapper id="contributing" className="py-20">
      <div className="container">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            🤝 Contribute to SniffGu@rd
          </h2>
          <p className="text-muted-foreground text-lg">We love your input! Help us build the best wireless security tool.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-10">
          {cards.map((c, i) => (
            <motion.div
              key={c.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              whileHover={{ y: -4 }}
              className="glass-card p-6 text-center"
            >
              <div className="text-4xl mb-4">{c.icon}</div>
              <h3 className="font-display font-bold text-foreground mb-2">{c.title}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{c.desc}</p>
            </motion.div>
          ))}
        </div>

        <div className="max-w-2xl mx-auto">
          <TerminalWindow title="contributing workflow" copyText={prCode}>
            {prCode.split('\n').map((line, i) => (
              <div key={i} className={line.startsWith('#') ? 'text-muted-foreground/50' : 'text-muted-foreground'}>
                {!line.startsWith('#') && <span className="text-success">$ </span>}
                {line}
              </div>
            ))}
          </TerminalWindow>
        </div>

        <p className="text-center text-xs text-muted-foreground/60 mt-8">
          Please be respectful and professional in all interactions within this project's ecosystem.
        </p>

        {/* Maintainer info */}
        <div className="text-center mt-8 text-xs text-muted-foreground/70 space-y-1">
          <p>Maintained by{' '}
            <a href="https://www.linkedin.com/in/rudra-sharma-714a7b259/" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Rudra Sharma</a>
            {' '}·{' '}
            <a href="https://rudrasharma.tech" target="_blank" rel="noopener noreferrer" className="hover:text-accent transition-colors">rudrasharma.tech</a>
            {' '}·{' '}
            <a href="https://github.com/Rudii-25/Sniffguard" target="_blank" rel="noopener noreferrer" className="hover:text-accent transition-colors">GitHub</a>
          </p>
        </div>
      </div>
    </SectionWrapper>
  );
}
