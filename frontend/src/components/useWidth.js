import { useEffect, useRef, useState } from "react";

// 컨테이너 너비를 추적해서 SVG 차트를 반응형으로 그림
export default function useWidth(initial = 600) {
  const ref = useRef(null);
  const [width, setWidth] = useState(initial);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}
