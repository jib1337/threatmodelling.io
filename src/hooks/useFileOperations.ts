import { useCallback } from 'react';
import type { ThreatModel } from '../data/schema';

export function useFileOperations() {
  const exportToFile = useCallback((model: ThreatModel) => {
    const blob = new Blob([JSON.stringify(model, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${model.name.toLowerCase().replace(/\s+/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);

  const importFromFile = useCallback((): Promise<ThreatModel> => {
    return new Promise((resolve, reject) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.json';

      input.onchange = async (event) => {
        const file = (event.target as HTMLInputElement).files?.[0];
        if (!file) {
          reject(new Error('No file selected'));
          return;
        }

        try {
          const text = await file.text();
          const model = JSON.parse(text) as ThreatModel;

          // Basic validation
          if (!model.version || !model.nodes || !model.edges) {
            throw new Error('Invalid threat model file');
          }

          resolve(model);
        } catch (err) {
          reject(err);
        }
      };

      input.click();
    });
  }, []);

  return { exportToFile, importFromFile };
}
