import React from 'react';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export const Card: React.FC<CardProps> = ({
  children,
  className = '',
  title,
  subtitle,
  action,
  ...props
}) => {
  return (
    <div
      className={`rounded-xl border border-slate-800 bg-slate-900/90 p-5 backdrop-blur shadow-sm ${className}`}
      {...props}
    >
      {(title || action) && (
        <div className="mb-4 flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div>
            {title && <h3 className="text-sm font-semibold text-slate-100 tracking-wide">{title}</h3>}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
};
