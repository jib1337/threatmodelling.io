import type { CloudProvider } from '../../data/schema';
import { useTheme } from '../../context/ThemeContext';
import { Box, CloudCog, Server, type LucideIcon } from 'lucide-react';
import AwsLogo from '../../assets/provider-logos/aws.svg';
import AwsLogoLight from '../../assets/provider-logos/aws-light.svg';
import GcpLogo from '../../assets/provider-logos/gcp.svg';
import AzureLogo from '../../assets/provider-logos/azure.svg';
import './ProviderIcon.css';

interface ProviderIconProps {
  provider: CloudProvider;
  size?: 'small' | 'medium' | 'large';
  className?: string;
}

const PROVIDER_LOGOS: Partial<Record<CloudProvider, string>> = {
  'aws': AwsLogo,
  'gcp': GcpLogo,
  'azure': AzureLogo,
};

const PROVIDER_LOGOS_LIGHT: Partial<Record<CloudProvider, string>> = {
  'aws': AwsLogoLight,
};

const FALLBACK_ICONS: Partial<Record<CloudProvider, string>> = {
  'aws': '☁️',
  'gcp': '🌐',
  'azure': '🔷',
  'actor': '👤',
};

const LUCIDE_ICONS: Partial<Record<CloudProvider, { icon: LucideIcon; color: string }>> = {
  'custom': { icon: Box, color: 'var(--provider-custom)' },
  'self-hosted': { icon: Server, color: 'var(--provider-self-hosted)' },
  'saas': { icon: CloudCog, color: 'var(--provider-saas)' },
};

const ICON_SIZES: Record<string, number> = {
  'small': 14,
  'medium': 20,
  'large': 28,
};

export default function ProviderIcon({ provider, size = 'medium', className = '' }: ProviderIconProps) {
  const { theme } = useTheme();
  const logo = (theme === 'light' && PROVIDER_LOGOS_LIGHT[provider]) || PROVIDER_LOGOS[provider];

  if (logo) {
    return (
      <img
        src={logo}
        alt={`${provider} logo`}
        className={`provider-icon provider-icon-${size} ${className}`}
      />
    );
  }

  const lucide = LUCIDE_ICONS[provider];
  if (lucide) {
    const Icon = lucide.icon;
    return (
      <span className={`provider-icon-emoji provider-icon-${size} ${className}`}>
        <Icon size={ICON_SIZES[size]} color={lucide.color} aria-label={`${provider} icon`} />
      </span>
    );
  }

  // Fallback to emoji (actor, or a cloud logo that failed to resolve)
  return (
    <span className={`provider-icon-emoji provider-icon-${size} ${className}`}>
      {FALLBACK_ICONS[provider]}
    </span>
  );
}
