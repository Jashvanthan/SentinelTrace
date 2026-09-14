

interface HashDisplayProps {
  hash?: string | null;
  truncateLength?: number;
}

export const HashDisplay: React.FC<HashDisplayProps> = ({ hash, truncateLength = 16 }) => {
  if (!hash) {
    return <span className="text-xs font-mono bg-gray-700/30 px-2 py-0.5 rounded">Not Available</span>;
  }
  const truncated = hash.length > truncateLength ? `${hash.slice(0, truncateLength)}…` : hash;
  return (
    <span className="text-xs font-mono bg-gray-700/30 px-2 py-0.5 rounded cursor-help" title={hash}>
      {truncated}
    </span>
  );
};
