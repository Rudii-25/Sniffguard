import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { Rocket, BookOpen } from 'lucide-react';
import { TerminalWindow } from './TerminalWindow';
import { ParticleBackground } from './ParticleBackground';

const commands = [
  '$ git clone https://github.com/Rudii-25/Sniffguard.git',
  '$ cd "sniffguard v2"',
  '$ pip install -r requirements.txt',
  '$ sudo python3 sniffguard.py',
];

const badges = [
  '🐍 Python 3.8+',
  '🐧 Linux Only',
  '📜 MIT License',
  '🟢 Status: Active',
  '🖥️ GUI: PyQt6',
];

function TypewriterTerminal() {
  const [lines, setLines] = useState<string[]>([]);
  const [currentLine, setCurrentLine] = useState(0);
  const [charIndex, setCharIndex] = useState(0);

  useEffect(() => {
    if (currentLine >= commands.length) return;
    const cmd = commands[currentLine];
    if (charIndex < cmd.length) {
      const t = setTimeout(() => {
        setLines((prev) => {
          const copy = [...prev];
          copy[currentLine] = cmd.slice(0, charIndex + 1);
          return copy;
        });
        setCharIndex(charIndex + 1);
      }, 30 + Math.random() * 30);
      return () => clearTimeout(t);
    } else {
      const t = setTimeout(() => {
        setCurrentLine(currentLine + 1);
        setCharIndex(0);
        setLines((prev) => [...prev, '']);
      }, 400);
      return () => clearTimeout(t);
    }
  }, [currentLine, charIndex]);

  return (
    <TerminalWindow title="sniffguard-v2 — bash" copyText={commands.map(c => c.replace('$ ', '')).join('\n')}>
      {lines.map((line, i) => (
        <div key={i} className="text-foreground">
          <span className="text-success">$</span>
          <span className="text-muted-foreground">{line.replace(/^\$/, '')}</span>
          {i === currentLine && currentLine < commands.length && (
            <span className="inline-block w-2 h-4 bg-accent ml-0.5 animate-pulse" />
          )}
        </div>
      ))}
    </TerminalWindow>
  );
}

export function HeroSection() {
  const sectionRef = useRef<HTMLDivElement>(null);

  return (
    <section id="hero" ref={sectionRef} className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Particle background */}
      <ParticleBackground />

      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-primary opacity-60 z-[1]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_hsl(207_100%_65%_/_0.08)_0%,_transparent_70%)] z-[1]" />
      
      {/* Scan line */}
      <div className="scan-line" />

      {/* Grid pattern */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(hsl(207 100% 65% / 0.3) 1px, transparent 1px), linear-gradient(90deg, hsl(207 100% 65% / 0.3) 1px, transparent 1px)`,
          backgroundSize: '60px 60px',
        }}
      />

      <div className="relative z-10 container text-center max-w-4xl mx-auto pt-20">
        {/* Live indicator */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="absolute top-24 right-6 flex items-center gap-2"
        >
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-xs font-mono text-success uppercase tracking-wider">Live</span>
        </motion.div>

        {/* Logo image */}
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: "spring", duration: 0.6, bounce: 0.2 }}
          className="mb-8"
        >
          <img
            src="logo.png"
            alt="SniffGu@rd Logo"
            className="mx-auto h-36 w-auto object-contain drop-shadow-[0_0_24px_rgba(0,242,254,0.45)] animate-pulse-glow"
          />
        </motion.div>

        {/* Title */}
        <motion.h1
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1, type: "spring", duration: 0.5 }}
          className="font-display font-bold text-gradient mb-4"
          style={{ fontSize: 'clamp(3rem, 8vw, 5rem)', letterSpacing: '-0.03em' }}
        >
          SniffGu@rd
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="text-sm font-mono uppercase tracking-[0.3em] text-muted-foreground mb-6"
        >
          V 2 . 0 · ADVANCED WIRELESS SECURITY AUDITING
        </motion.p>

        {/* Description */}
        <motion.p
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="text-muted-foreground text-lg max-w-2xl mx-auto mb-8 leading-relaxed"
        >
          A professional-grade wireless network security auditing tool. Scan nearby networks, detect rogue access points, analyze signal strengths, and produce detailed security reports — all from an elegant GUI.
        </motion.p>

        {/* Badges */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="flex flex-wrap items-center justify-center gap-2 mb-10"
        >
          {badges.map((badge) => (
            <span
              key={badge}
              className="text-xs font-mono px-3 py-1.5 rounded-full border border-border bg-surface-1 text-muted-foreground"
            >
              {badge}
            </span>
          ))}
        </motion.div>

        {/* CTA Buttons */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="flex items-center justify-center gap-4 mb-12"
        >
          <a
            href="#installation"
            className="inline-flex items-center gap-2 bg-gradient-accent text-primary-foreground font-semibold px-6 py-3 rounded-lg hover:scale-[1.03] active:scale-[0.97] transition-transform"
          >
            <Rocket size={18} />
            Get Started
          </a>
          <a
            href="#usage"
            className="inline-flex items-center gap-2 glass px-6 py-3 rounded-lg font-semibold text-foreground hover:border-primary/40 transition-all"
          >
            <BookOpen size={18} />
            View Docs
          </a>
        </motion.div>

        {/* Terminal */}
        <motion.div
          initial={{ y: 30, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.7 }}
          className="max-w-xl mx-auto text-left"
        >
          <TypewriterTerminal />
        </motion.div>
      </div>
    </section>
  );
}
