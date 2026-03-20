import { AlertTriangle } from 'lucide-react';
import { SectionWrapper } from './SectionWrapper';

export function LegalBanner() {
  return (
    <SectionWrapper id="legal" className="py-12">
      <div className="container">
        <div className="border border-warning/20 bg-warning/5 rounded-xl p-6 flex items-start gap-4">
          <AlertTriangle size={24} className="text-warning flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-display font-bold text-warning mb-2">⚠️ Legal Disclaimer</h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              SniffGu@rd is designed strictly for authorized security auditing and educational purposes. Scanning networks you do not own or do not have explicit written permission to test is illegal in most jurisdictions. The developers assume no liability for misuse of this tool. Use responsibly and ethically.
            </p>
          </div>
        </div>
      </div>
    </SectionWrapper>
  );
}
