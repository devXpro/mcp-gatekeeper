import { cva, type VariantProps } from 'class-variance-authority'
import { motion } from 'motion/react'
import type { AnchorHTMLAttributes, ComponentProps, ReactNode } from 'react'
import { Link, type LinkProps } from 'react-router'
import { cn } from '../../lib/cn'
import { spring } from '../../lib/motion'
import { Spinner } from './spinner'

// Buttons (DESIGN.md §6): one filled button per screen at most; everything else tinted, plain or a row.
const buttonVariants = cva(
  'relative inline-flex select-none items-center justify-center gap-2 whitespace-nowrap font-semibold transition-colors disabled:pointer-events-none disabled:opacity-40 aria-disabled:pointer-events-none aria-disabled:opacity-40',
  {
    variants: {
      variant: {
        filled: 'bg-accent-fill text-white hover:brightness-110',
        tinted: 'bg-accent-tint text-accent-tinted hover:brightness-110',
        plain: 'bg-transparent text-accent-text hover:opacity-80',
        destructive: 'bg-fill text-danger-text hover:brightness-110',
        'destructive-filled': 'bg-danger-fill text-white hover:brightness-110',
      },
      size: {
        lg: 'h-[50px] w-full rounded-full px-5 type-headline',
        md: 'h-11 rounded-md px-4 type-headline',
        sm: 'h-8 rounded-full px-3.5 text-[15px] leading-5 font-semibold',
      },
    },
    compoundVariants: [{ variant: 'plain', size: 'sm', className: 'px-1' }],
    defaultVariants: { variant: 'filled', size: 'md' },
  },
)

type ButtonVariantProps = VariantProps<typeof buttonVariants>

export interface ButtonProps extends Omit<ComponentProps<typeof motion.button>, 'children'>, ButtonVariantProps {
  icon?: ReactNode
  loading?: boolean
  children?: ReactNode
}

export function Button({ className, variant, size, icon, loading, disabled, children, type, ...props }: ButtonProps) {
  return (
    <motion.button
      type={type ?? 'button'}
      whileTap={{ scale: 0.97 }}
      transition={spring.snappy}
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading ? <Spinner size="sm" className="text-current" /> : icon}
      {children}
    </motion.button>
  )
}

export interface ButtonLinkProps extends LinkProps, ButtonVariantProps {
  icon?: ReactNode
}

export function ButtonLink({ className, variant, size, icon, children, ...props }: ButtonLinkProps) {
  return (
    <Link className={cn(buttonVariants({ variant, size }), className)} {...props}>
      {icon}
      {children}
    </Link>
  )
}

/** ButtonAnchor is an external link that looks like a button; it opens in a new tab without an opener. */
export function ButtonAnchor({
  className,
  variant,
  size,
  icon,
  children,
  ...props
}: AnchorHTMLAttributes<HTMLAnchorElement> & ButtonVariantProps & { icon?: ReactNode }) {
  return (
    <a target="_blank" rel="noopener noreferrer" className={cn(buttonVariants({ variant, size }), className)} {...props}>
      {icon}
      {children}
    </a>
  )
}

/** IconButton has a 44 px hit area around a 22 px glyph (DESIGN.md §6). */
export function IconButton({
  className,
  label,
  children,
  ...props
}: Omit<ComponentProps<'button'>, 'aria-label'> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        'inline-flex size-11 shrink-0 items-center justify-center rounded-full text-accent transition-opacity hover:opacity-75 active:opacity-50 disabled:opacity-40 [&_svg]:size-[22px]',
        className,
      )}
      {...props}
    >
      {children}
    </button>
  )
}
