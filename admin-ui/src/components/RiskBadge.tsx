import { Badge } from '@fluentui/react-components';
import type { BadgeProps } from '@fluentui/react-components';

interface RiskBadgeProps {
  level: string;
}

const colorMap: Record<string, BadgeProps['color']> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'success',
  info: 'informative',
  'true': 'danger',
  'false': 'success',
  yes: 'danger',
  no: 'success',
};

export function RiskBadge({ level }: RiskBadgeProps) {
  const normalized = level?.toLowerCase().trim() ?? '';
  const color = colorMap[normalized] ?? 'informative';

  return (
    <Badge
      appearance="filled"
      color={color}
      className="inline-badge"
    >
      {level}
    </Badge>
  );
}
