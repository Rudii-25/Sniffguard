import { SectionWrapper } from './SectionWrapper';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';

const faqs = [
  { q: 'Does SniffGu@rd work on Windows or macOS?', a: 'No. SniffGu@rd requires Linux because it uses Linux-specific networking commands (iwconfig, iw, ip) and low-level kernel interfaces for monitor mode support.' },
  { q: 'Why do I need root/sudo privileges?', a: 'Monitor mode and packet capture require direct access to network hardware at the kernel level — these operations are restricted to root on Linux for security reasons.' },
  { q: 'What wireless adapters are supported?', a: 'Any Linux-compatible wireless adapter that supports monitor mode. External high-gain adapters like the Alfa AWUS036ACH provide optimal range and compatibility.' },
  { q: 'Is this tool legal to use?', a: 'SniffGu@rd is designed for authorized security auditing only. Scanning networks you do not own or do not have explicit written permission to test is illegal in most jurisdictions. Always get written authorization before scanning.' },
  { q: 'Can I export scan results?', a: 'Yes! Use File → Export in the GUI to save your scan data as CSV or JSON for further analysis or reporting.' },
  { q: 'What Python version is required?', a: 'Python 3.8 or higher is required. We recommend using a virtual environment to avoid dependency conflicts.' },
  { q: 'How is SniffGu@rd different from airodump-ng or Kismet?', a: 'SniffGu@rd provides a clean, beginner-friendly PyQt6 GUI on top of battle-tested Scapy packet capture — making it ideal for those who want power without the terminal-only complexity of airodump-ng or Kismet.' },
];

export function FAQSection() {
  return (
    <SectionWrapper id="faq" className="py-24">
      <div className="container max-w-3xl">
        <div className="text-center mb-16">
          <h2 className="font-display font-bold text-foreground mb-4" style={{ fontSize: 'clamp(2rem, 5vw, 2.5rem)' }}>
            ❓ Frequently Asked Questions
          </h2>
        </div>

        <Accordion type="single" collapsible className="space-y-3">
          {faqs.map((faq, i) => (
            <AccordionItem
              key={i}
              value={`faq-${i}`}
              className="glass-card px-6 border-none data-[state=open]:border-l-2 data-[state=open]:border-l-primary"
            >
              <AccordionTrigger className="text-foreground font-display text-sm font-semibold hover:no-underline py-4">
                {faq.q}
              </AccordionTrigger>
              <AccordionContent className="text-muted-foreground text-sm leading-relaxed pb-4">
                {faq.a}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </div>
    </SectionWrapper>
  );
}
