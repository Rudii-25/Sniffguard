import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, Star } from 'lucide-react';

const navLinks = [
  { label: 'Home', href: '#hero' },
  { label: 'Features', href: '#features' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Installation', href: '#installation' },
  { label: 'Usage', href: '#usage' },
  { label: 'Architecture', href: '#architecture' },
  { label: 'FAQ', href: '#faq' },
];

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('#hero');

  const handleScroll = useCallback(() => {
    setScrolled(window.scrollY > 80);

    // Scroll spy: find which section is most visible
    const sections = navLinks.map((l) => l.href.replace('#', ''));
    let current = sections[0];

    for (const id of sections) {
      const el = document.getElementById(id);
      if (el) {
        const rect = el.getBoundingClientRect();
        // Section is "active" when its top is above the middle of the viewport
        if (rect.top <= 150) {
          current = id;
        }
      }
    }
    setActiveSection(`#${current}`);
  }, []);

  useEffect(() => {
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);

  return (
    <motion.nav
      className="fixed top-0 left-0 right-0 z-50 transition-all duration-300"
      style={{
        backgroundColor: scrolled ? 'hsla(240, 14%, 4%, 0.9)' : 'transparent',
        backdropFilter: scrolled ? 'blur(12px)' : 'none',
        borderBottom: scrolled ? '1px solid hsl(207 100% 65% / 0.1)' : '1px solid transparent',
      }}
    >
      <div className="container mx-auto flex items-center justify-between h-16">
        <a href="#hero" className="flex items-center gap-1">
          <img
            src="logo.png"
            alt="SniffGu@rd Logo"
            className="h-9 w-auto object-contain drop-shadow-[0_0_8px_rgba(0,242,254,0.5)]"
          />
          <span className="text-[10px] font-mono font-semibold bg-primary/20 text-primary px-2 py-0.5 rounded-full border border-primary/30 ml-1">
            V2.0
          </span>
        </a>

        <div className="hidden lg:flex items-center gap-6">
          {navLinks.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className={`relative text-xs uppercase tracking-widest transition-colors ${
                activeSection === l.href
                  ? 'text-accent'
                  : 'text-muted-foreground hover:text-accent'
              }`}
            >
              {l.label}
              {activeSection === l.href && (
                <motion.div
                  layoutId="nav-indicator"
                  className="absolute -bottom-1 left-0 right-0 h-px bg-accent"
                  transition={{ type: 'spring', duration: 0.4, bounce: 0.15 }}
                />
              )}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <a
            href="https://github.com/Rudii-25/Sniffguard"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:flex items-center gap-2 glass px-4 py-2 rounded-lg text-sm font-medium text-foreground hover:border-primary/40 transition-all"
          >
            <Star size={14} className="text-accent" />
            Star on GitHub
          </a>
          <button
            className="lg:hidden text-muted-foreground hover:text-foreground transition-colors"
            onClick={() => setMobileOpen(!mobileOpen)}
          >
            {mobileOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="lg:hidden overflow-hidden glass"
          >
            <div className="container py-4 flex flex-col gap-3">
              {navLinks.map((l) => (
                <a
                  key={l.href}
                  href={l.href}
                  onClick={() => setMobileOpen(false)}
                  className={`text-sm uppercase tracking-widest transition-colors py-2 ${
                    activeSection === l.href
                      ? 'text-accent border-l-2 border-accent pl-3'
                      : 'text-muted-foreground hover:text-accent'
                  }`}
                >
                  {l.label}
                </a>
              ))}
              <a
                href="https://github.com/Rudii-25/Sniffguard"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 glass px-4 py-2 rounded-lg text-sm font-medium text-foreground w-fit"
              >
                <Star size={14} className="text-accent" />
                Star on GitHub
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.nav>
  );
}
