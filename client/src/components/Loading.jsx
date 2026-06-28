export default function Loading({ visible }) {
  if (!visible) return null;
  return (
    <div className="loading-overlay">
      <div className="spinner" />
      <p>Processing packets…</p>
    </div>
  );
}
