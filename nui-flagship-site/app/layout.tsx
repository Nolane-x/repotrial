import type { Metadata } from 'next';
import './globals.css';
import './responsive-overrides.css';
import './cinematic-m2.css';
import './cinematic-m3.css';
import './mobile-m2-overrides.css';
import './reduced-motion-overrides.css';

export const metadata: Metadata = {
  title: 'Nolane — Intelligence Is a System',
  description: 'An experiential visualization of Nolane UI Intelligence: routing, research, craft, evidence, critics and verification as one living architecture.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-motion="full">
      <body>{children}</body>
    </html>
  );
}
