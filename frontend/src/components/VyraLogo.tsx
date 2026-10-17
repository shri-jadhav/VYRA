import React from 'react';

interface VyraLogoProps {
  className?: string;
  size?: number;
}

export const VyraLogo: React.FC<VyraLogoProps> = ({
  className = '',
  size = 28,
}) => {
  return (
    <div className={`relative inline-flex items-center justify-center shrink-0 ${className}`}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 48 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="relative z-10"
      >
        <defs>
          <linearGradient id="appleMonoGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="50%" stopColor="#D6D6D6" />
            <stop offset="100%" stopColor="#8E8E93" />
          </linearGradient>
          <linearGradient id="appleMonoGrad2" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#A1A1A6" />
            <stop offset="60%" stopColor="#48484A" />
            <stop offset="100%" stopColor="#1C1C1E" />
          </linearGradient>
          <linearGradient id="appleDarkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#2C2C2E" />
            <stop offset="100%" stopColor="#101010" />
          </linearGradient>
        </defs>

        {/* Outer Precision Hexagonal Shield Baseline */}
        <polygon
          points="24,3 43,10 43,30 24,45 5,30 5,10"
          stroke="url(#appleMonoGrad1)"
          strokeWidth="1.2"
          strokeOpacity="0.4"
          fill="none"
        />

        {/* Left Wing of the V */}
        <path
          d="M7 12L24 40L21 42L4 14L7 12Z"
          fill="url(#appleMonoGrad2)"
          opacity="0.95"
        />
        <path
          d="M8 12L24 39L20 28L12 14L8 12Z"
          fill="url(#appleMonoGrad1)"
        />

        {/* Right Wing of the V (Overlapping) */}
        <path
          d="M41 12L24 40L27 42L44 14L41 12Z"
          fill="url(#appleMonoGrad2)"
          opacity="0.95"
        />
        <path
          d="M40 12L24 39L28 28L36 14L40 12Z"
          fill="url(#appleMonoGrad1)"
        />

        {/* Center Precision Core Prism */}
        <polygon
          points="24,14 29,24 24,34 19,24"
          fill="url(#appleDarkGrad)"
          stroke="url(#appleMonoGrad1)"
          strokeWidth="1.2"
        />

        {/* Center Precision Pillar */}
        <line
          x1="24"
          y1="8"
          x2="24"
          y2="20"
          stroke="#FFFFFF"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
        <circle cx="24" cy="24" r="1.75" fill="#FFFFFF" />
      </svg>
    </div>
  );
};
