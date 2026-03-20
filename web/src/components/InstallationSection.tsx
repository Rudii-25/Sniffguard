import { SectionWrapper } from './SectionWrapper';
import { TerminalWindow } from './TerminalWindow';
import { AlertTriangle } from 'lucide-react';

const prerequisites = [
  { label: 'OS', value: 'Linux (Ubuntu / Debian / Kali)' },
  { label: 'Python', value: '3.8 or higher' },
  { label: 'Privileges', value: 'Root / sudo required' },
  { label: 'Tools', value: 'iwconfig, iw, iproute2, wireless-tools' },
];

const steps = [
  { title: 'Step 1 — Clone', code: 'git clone https://github.com/Rudii-25/Sniffguard.git\ncd "sniffguard v2"' },
  { title: 'Step 2 — Install System Dependencies', code: 'sudo apt update\nsudo apt install wireless-tools iw iproute2 python3-pip' },
  { title: 'Step 3 — Create Virtual Environment', code: 'python3 -m venv venv\nsource venv/bin/activate\npip install -r requirements.txt' },
  { title: 'Step 4 — Run', code: 'sudo ./venv/bin/python sniffguard.py' },
];

export function InstallationSection() {
  return (
    <SectionWrapper id="installation" className="py-24">
      <div className="container">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            🛠️ Installation Guide
          </h2>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
          {/* Prerequisites */}
          <div className="lg:col-span-2">
            <div className="glass-card p-6">
              <h3 className="font-display font-bold text-foreground mb-4">Prerequisites</h3>
              <div className="border-t border-border" />
              <div className="mt-4 space-y-3">
                {prerequisites.map((p) => (
                  <div key={p.label} className="flex justify-between text-sm">
                    <span className="text-muted-foreground font-mono">{p.label}</span>
                    <span className="text-foreground text-right">{p.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Steps */}
          <div className="lg:col-span-3 space-y-4">
            {steps.map((s) => (
              <div key={s.title}>
                <h4 className="font-display text-sm font-semibold text-foreground mb-2">{s.title}</h4>
                <TerminalWindow title="bash" copyText={s.code}>
                  {s.code.split('\n').map((line, i) => (
                    <div key={i}>
                      <span className="text-success">$ </span>
                      <span className="text-muted-foreground">{line}</span>
                    </div>
                  ))}
                </TerminalWindow>
              </div>
            ))}
          </div>
        </div>

        {/* Warning */}
        <div className="mt-8 border-l-4 border-warning bg-warning/5 p-4 rounded-r-lg flex items-start gap-3">
          <AlertTriangle size={20} className="text-warning flex-shrink-0 mt-0.5" />
          <p className="text-sm text-muted-foreground">
            <strong className="text-warning">Warning:</strong> SniffGu@rd V2 requires Linux and Root Privileges to function. It interacts directly with network hardware using low-level kernel interfaces.
          </p>
        </div>
      </div>
    </SectionWrapper>
  );
}
