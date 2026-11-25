import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import { ThreatModelProvider, useThreatModel } from '../../context/ThreatModelContext';
import type { ThreatModel } from '../../data/schema';
import {
  DEFAULT_PATHWAY_MITIGATION_SETTINGS,
  MAX_CUSTOM_CONTROL_LENGTH,
  MAX_CUSTOM_CONTROLS_PER_SCOPE,
} from '../../data/schema';
import { buildCustomControlKey } from '../../utils/controlFingerprint';
import ControlsSection, { type CatalogueControlItem } from './ControlsSection';

const SCOPE = 'connection:t-1';

type ModelApi = ReturnType<typeof useThreatModel>;

function renderSection(catalogueControls: CatalogueControlItem[] = []) {
  const api: { current: ModelApi | null } = { current: null };
  function Probe() {
    api.current = useThreatModel();
    return null;
  }
  render(
    <ThreatModelProvider>
      <ControlsSection catalogueControls={catalogueControls} scopeKey={SCOPE} />
      <Probe />
    </ThreatModelProvider>,
  );
  return {
    get model() { return api.current!; },
    customControls: () => api.current!.customControls[SCOPE] ?? [],
  };
}

function addViaUi(text: string) {
  fireEvent.click(screen.getByRole('button', { name: /add control/i }));
  const input = screen.getByRole('textbox', { name: 'New custom control' });
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

describe('ControlsSection', () => {
  it('shows the heading and an add button even with no catalogue controls', () => {
    renderSection();
    expect(screen.getByRole('heading', { name: 'Mitigating Controls' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /add control/i })).toBeInTheDocument();
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('renders and ticks catalogue controls', () => {
    const h = renderSection([{ id: 'c1', key: 'connection:t-1::abcd1234', text: 'Enable MFA' }]);
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable MFA' }));
    expect(h.model.implementedControls['connection:t-1::abcd1234']).toBe(true);
  });

  it('adds a custom control with Enter and shows it, with edit and delete, after the catalogue ones', () => {
    const h = renderSection([{ id: 'c1', key: 'k1', text: 'Enable MFA' }]);
    addViaUi('  Quarterly access review ');
    expect(h.customControls()).toEqual([{ id: expect.any(String), description: 'Quarterly access review' }]);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();

    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[1]).toHaveTextContent('Quarterly access review');
    expect(within(items[1]).getByRole('button', { name: /^Edit custom control/ })).toBeVisible();
    expect(within(items[1]).getByRole('button', { name: /^Delete custom control/ })).toBeVisible();
    // Catalogue controls stay read-only
    expect(within(items[0]).queryByRole('button')).not.toBeInTheDocument();
  });

  it('adds with the Add button too', () => {
    const h = renderSection();
    fireEvent.click(screen.getByRole('button', { name: /add control/i }));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'Via button' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(h.customControls()[0].description).toBe('Via button');
  });

  it('disables Add for blank text and ignores Enter', () => {
    const h = renderSection();
    fireEvent.click(screen.getByRole('button', { name: /add control/i }));
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: '   ' } });
    expect(screen.getByRole('button', { name: 'Add' })).toBeDisabled();
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(h.customControls()).toEqual([]);
    expect(screen.getByRole('textbox')).toBeInTheDocument();
  });

  it('cancels with Escape without adding anything', () => {
    const h = renderSection();
    fireEvent.click(screen.getByRole('button', { name: /add control/i }));
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'Never mind' } });
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(h.customControls()).toEqual([]);
    expect(screen.getByRole('button', { name: /add control/i })).toBeInTheDocument();
  });

  it('limits input to 200 characters and shows a counter near the limit', () => {
    renderSection();
    fireEvent.click(screen.getByRole('button', { name: /add control/i }));
    const input = screen.getByRole('textbox');
    expect(input).toHaveAttribute('maxLength', String(MAX_CUSTOM_CONTROL_LENGTH));

    fireEvent.change(input, { target: { value: 'a'.repeat(100) } });
    expect(screen.queryByText(/\/200$/)).not.toBeInTheDocument();
    fireEvent.change(input, { target: { value: 'a'.repeat(185) } });
    expect(screen.getByText('185/200')).toBeInTheDocument();
  });

  it('ticks a custom control by id', () => {
    const h = renderSection();
    addViaUi('Tick me');
    const { id } = h.customControls()[0];
    fireEvent.click(screen.getByRole('checkbox', { name: /Tick me/ }));
    expect(h.model.implementedControls[buildCustomControlKey(SCOPE, id)]).toBe(true);
  });

  it('edits in place, keeping the id and tick', () => {
    const h = renderSection();
    addViaUi('Original');
    const { id } = h.customControls()[0];
    fireEvent.click(screen.getByRole('checkbox', { name: /Original/ }));

    fireEvent.click(screen.getByRole('button', { name: 'Edit custom control: Original' }));
    const input = screen.getByRole('textbox', { name: 'Edit custom control' });
    expect(input).toHaveValue('Original');
    fireEvent.change(input, { target: { value: 'Reworded' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(h.customControls()).toEqual([{ id, description: 'Reworded' }]);
    expect(h.model.implementedControls[buildCustomControlKey(SCOPE, id)]).toBe(true);
    expect(screen.getByRole('checkbox', { name: /Reworded/ })).toBeChecked();
  });

  it('leaves the text unchanged when an edit is cancelled', () => {
    const h = renderSection();
    addViaUi('Keep me');
    fireEvent.click(screen.getByRole('button', { name: 'Edit custom control: Keep me' }));
    const input = screen.getByRole('textbox', { name: 'Edit custom control' });
    fireEvent.change(input, { target: { value: 'Changed' } });
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(h.customControls()[0].description).toBe('Keep me');
  });

  it('deletes a custom control', () => {
    const h = renderSection();
    addViaUi('Delete me');
    fireEvent.click(screen.getByRole('button', { name: 'Delete custom control: Delete me' }));
    expect(h.customControls()).toEqual([]);
    expect(screen.queryByText('Delete me')).not.toBeInTheDocument();
  });

  it('replaces the add button with a note once the scope is full', async () => {
    const h = renderSection();
    const full: ThreatModel = {
      version: '1.6', name: 'Full', createdAt: '', updatedAt: '',
      nodes: [], edges: [], zones: [],
      pathwayMitigationSettings: DEFAULT_PATHWAY_MITIGATION_SETTINGS,
      customControls: {
        [SCOPE]: Array.from({ length: MAX_CUSTOM_CONTROLS_PER_SCOPE }, (_, i) => ({ id: `c${i}`, description: `Control ${i}` })),
      },
    };
    await act(async () => { await h.model.importModel(full); });
    expect(screen.queryByRole('button', { name: /add control/i })).not.toBeInTheDocument();
    expect(screen.getByText(/maximum for one threat/)).toBeInTheDocument();
  });
});
