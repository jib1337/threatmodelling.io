import type { Node } from '@xyflow/react';
import type { ZoneNodeData } from '../data/schema';

interface Position {
  x: number;
  y: number;
}

interface BoundaryBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Get the bounds of a boundary node
 * Checks multiple possible locations for dimensions (React Flow may store them differently)
 */
function getBoundaryBounds(boundary: Node<ZoneNodeData>): BoundaryBounds {
  // React Flow may store dimensions in different places depending on how they were set
  // Check: node.width/height (set by NodeResizer), node.measured, node.style
  const width = boundary.width
    ?? boundary.measured?.width
    ?? (boundary.style?.width as number)
    ?? 300;
  const height = boundary.height
    ?? boundary.measured?.height
    ?? (boundary.style?.height as number)
    ?? 200;

  return {
    x: boundary.position.x,
    y: boundary.position.y,
    width,
    height,
  };
}

/**
 * Check if a position is inside a boundary's bounds
 * @param position - The position to check (absolute coordinates)
 * @param boundary - The boundary node to check against
 * @param padding - Optional padding to add inside the boundary (for header area)
 * @returns true if position is inside the boundary
 */
export function isPositionInBoundary(
  position: Position,
  boundary: Node<ZoneNodeData>,
  padding: number = 40 // Account for header height
): boolean {
  const bounds = getBoundaryBounds(boundary);

  return (
    position.x >= bounds.x &&
    position.x <= bounds.x + bounds.width &&
    position.y >= bounds.y + padding && // Start below header
    position.y <= bounds.y + bounds.height
  );
}

/**
 * Find the boundary that contains a given position
 * @param position - The position to check (absolute coordinates)
 * @param boundaries - Array of boundary nodes to search
 * @returns The boundary containing the position, or null if none
 */
export function findBoundaryAtPosition(
  position: Position,
  boundaries: Node<ZoneNodeData>[]
): Node<ZoneNodeData> | null {
  // Check boundaries in reverse order (newer ones are rendered on top)
  for (let i = boundaries.length - 1; i >= 0; i--) {
    const boundary = boundaries[i];
    if (isPositionInBoundary(position, boundary)) {
      return boundary;
    }
  }
  return null;
}

/**
 * Calculate the center position of a node for boundary detection
 * @param nodePosition - The node's position (top-left corner)
 * @param nodeWidth - The node's width (default: 160 for TechNode)
 * @param nodeHeight - The node's height (default: 100 for TechNode)
 * @returns The center position of the node
 */
export function getNodeCenterPosition(
  nodePosition: Position,
  nodeWidth: number = 160,
  nodeHeight: number = 100
): Position {
  return {
    x: nodePosition.x + nodeWidth / 2,
    y: nodePosition.y + nodeHeight / 2,
  };
}

/**
 * Convert an absolute position to a position relative to a boundary
 * @param absolutePosition - The absolute position
 * @param boundaryPosition - The boundary's position
 * @returns The position relative to the boundary's origin
 */
export function calculateRelativePosition(
  absolutePosition: Position,
  boundaryPosition: Position
): Position {
  return {
    x: absolutePosition.x - boundaryPosition.x,
    y: absolutePosition.y - boundaryPosition.y,
  };
}

/**
 * Convert a relative position to an absolute position
 * @param relativePosition - The position relative to a boundary
 * @param boundaryPosition - The boundary's position
 * @returns The absolute position
 */
export function calculateAbsolutePosition(
  relativePosition: Position,
  boundaryPosition: Position
): Position {
  return {
    x: relativePosition.x + boundaryPosition.x,
    y: relativePosition.y + boundaryPosition.y,
  };
}
