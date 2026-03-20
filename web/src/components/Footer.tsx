import { Shield, Github, Linkedin, Globe, ExternalLink } from 'lucide-react';

const productLinks = [
  { label: 'Features', href: '#features' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Installation', href: '#installation' },
  { label: 'Usage', href: '#usage' },
  { label: 'Architecture', href: '#architecture' },
  { label: 'FAQ', href: '#faq' },
];

const resourceLinks = [
  { label: 'GitHub Repository', href: 'https://github.com/Rudii-25/Sniffguard' },
  { label: 'Documentation', href: '#usage' },
  { label: 'Report Issues', href: 'https://github.com/Rudii-25/Sniffguard/issues' },
  { label: 'Project Website', href: 'https://rudii-25.github.io/Sniffguard/' },
];

const legalLinks = [
  { label: 'MIT License', href: 'https://github.com/Rudii-25/Sniffguard/blob/main/LICENSE' },
  { label: 'Disclaimer', href: '#legal' },
];

export function Footer() {
  return (
    <footer className="relative border-t border-primary/10">
      {/* Glowing divider */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-1/2 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />

      <div className="container py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-2 md:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              <Shield size={20} className="text-accent glow-cyan" />
              <span className="font-display font-bold text-gradient">SniffGu@rd</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed mb-4">
              Professional wireless network security auditing tool by Rudra Sharma.
            </p>
            {/* Social Links */}
            <div className="flex items-center gap-3">
              <a
                href="https://github.com/Rudii-25/Sniffguard"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-accent transition-colors"
                title="GitHub"
              >
                <Github size={16} />
              </a>
              <a
                href="https://www.linkedin.com/in/rudra-sharma-714a7b259/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-accent transition-colors"
                title="LinkedIn"
              >
                <Linkedin size={16} />
              </a>
              <a
                href="https://rudrasharma.tech"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-accent transition-colors"
                title="Personal Website"
              >
                <Globe size={16} />
              </a>
            </div>
          </div>

          {/* Product */}
          <div>
            <h4 className="font-display text-xs uppercase tracking-wider text-foreground mb-4">Product</h4>
            <div className="space-y-2">
              {productLinks.map((l) => (
                <a key={l.label} href={l.href} className="block text-sm text-muted-foreground hover:text-accent transition-colors">{l.label}</a>
              ))}
            </div>
          </div>

          {/* Resources */}
          <div>
            <h4 className="font-display text-xs uppercase tracking-wider text-foreground mb-4">Resources</h4>
            <div className="space-y-2">
              {resourceLinks.map((l) => (
                <a key={l.label} href={l.href} target={l.href.startsWith('http') ? '_blank' : undefined} rel="noopener noreferrer" className="block text-sm text-muted-foreground hover:text-accent transition-colors">{l.label}</a>
              ))}
            </div>
          </div>

          {/* Legal */}
          <div>
            <h4 className="font-display text-xs uppercase tracking-wider text-foreground mb-4">Legal</h4>
            <div className="space-y-2">
              {legalLinks.map((l) => (
                <a key={l.label} href={l.href} target={l.href.startsWith('http') ? '_blank' : undefined} rel="noopener noreferrer" className="block text-sm text-muted-foreground hover:text-accent transition-colors">{l.label}</a>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="border-t border-border mt-8 pt-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-muted-foreground/60">
          <span>
            Made with ❤️ by{' '}
            <a
              href="https://www.linkedin.com/in/rudra-sharma-714a7b259/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              Rudra Sharma
            </a>
            {' '}|{' '}
            <a
              href="https://rudrasharma.tech"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-accent transition-colors"
            >
              rudrasharma.tech
            </a>
          </span>
          <span>© 2026 Rudra Sharma. MIT License | SniffGu@rd V2</span>
        </div>
      </div>
    </footer>
  );
}
