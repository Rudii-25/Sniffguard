import { Navbar } from '@/components/Navbar';
import { HeroSection } from '@/components/HeroSection';
import { StatsBar } from '@/components/StatsBar';
import { FeaturesSection } from '@/components/FeaturesSection';
import { HowItWorksSection } from '@/components/HowItWorksSection';
import { InstallationSection } from '@/components/InstallationSection';
import { UsageSection } from '@/components/UsageSection';
import { ArchitectureSection } from '@/components/ArchitectureSection';
import { ContributingSection } from '@/components/ContributingSection';
import { FAQSection } from '@/components/FAQSection';
import { LegalBanner } from '@/components/LegalBanner';
import { Footer } from '@/components/Footer';

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <HeroSection />
      <StatsBar />
      <FeaturesSection />
      <HowItWorksSection />
      <InstallationSection />
      <UsageSection />
      <ArchitectureSection />
      <ContributingSection />
      <FAQSection />
      <LegalBanner />
      <Footer />
    </div>
  );
};

export default Index;
