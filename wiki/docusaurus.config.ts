import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'NestJS - Cryptography',
  tagline: 'Secure NestJS cryptography module 🔐',
  favicon: 'img/nestjs_favicon.ico',

  url: 'https://nestjs-cryptography.thewolfx41.dev',
  baseUrl: '/',

  organizationName: 'mjorgegulab',
  projectName: 'nestjs-cryptography',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/mjorgegulab/nestjs-cryptography',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],

  themeConfig: {
    image: 'img/profile.png',
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: 'NestJS - Cryptography',
      logo: {
        alt: 'NestJS Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          type: 'docsVersionDropdown',
          position: 'right',
        },
        {
          href: 'https://github.com/mjorgegulab/nestjs-cryptography',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/intro',
            },
          ],
        },
        {
          title: 'Project',
          items: [
            {
              label: 'Issues',
              href: 'https://github.com/mjorgegulab/nestjs-cryptography/issues',
            },
            {
              label: 'Contribute',
              href: 'https://github.com/mjorgegulab/nestjs-cryptography/issues',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'Stack Overflow',
              href: 'https://stackoverflow.com/questions/tagged/nestjs',
            }
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/mjorgegulab',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Marc Jorge`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      defaultLanguage: 'typescript',
    },
    mermaid: {
      theme: {dark: 'neutral'},
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
