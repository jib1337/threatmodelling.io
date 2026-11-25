import { useState, useRef, useEffect, memo } from 'react';
import { Plus, Pencil, Trash2 } from 'lucide-react';
import type { CustomControl } from '../../data/schema';
import { MAX_CUSTOM_CONTROL_LENGTH, MAX_CUSTOM_CONTROLS_PER_SCOPE } from '../../data/schema';
import { useActions, useThreats } from '../../context/ThreatModelContext';
import { buildCustomControlKey, normalizeCustomControlDescription } from '../../utils/controlFingerprint';
import './ControlsSection.css';

export interface CatalogueControlItem {
  // React key; stable for the life of the card
  id: string;
  // implementedControls key (buildControlKey)
  key: string;
  text: string;
}

interface ControlsSectionProps {
  catalogueControls: CatalogueControlItem[];
  // CustomControlsMap scope for this card (buildCustomControlScope)
  scopeKey: string;
}

// Show the remaining-character count once the user is this close to the cap
const COUNTER_THRESHOLD = MAX_CUSTOM_CONTROL_LENGTH - 20;

// "Mitigating Controls" for one threat card: the catalogue's controls, then
// any the user has added, then an inline field for adding more. Shared by
// ThreatCard, ConnectionThreatCard and ZoneThreatCard.
export default memo(function ControlsSection({ catalogueControls, scopeKey }: ControlsSectionProps) {
  const { setControlImplemented, addCustomControl } = useActions();
  const { implementedControls, customControls } = useThreats();
  const custom = Object.prototype.hasOwnProperty.call(customControls, scopeKey)
    ? customControls[scopeKey]
    : [];
  const [isAdding, setIsAdding] = useState(false);
  const atCap = custom.length >= MAX_CUSTOM_CONTROLS_PER_SCOPE;

  return (
    <div className="threat-section">
      <h4>Mitigating Controls</h4>
      {(catalogueControls.length > 0 || custom.length > 0) && (
        <ul className="controls-list">
          {catalogueControls.map(control => {
            const implemented = !!implementedControls[control.key];
            return (
              <li key={control.id} className={`control-item ${implemented ? 'implemented' : ''}`}>
                <label className="control-checkbox-label">
                  <input
                    type="checkbox"
                    className="control-checkbox"
                    checked={implemented}
                    onChange={e => setControlImplemented(control.key, e.target.checked)}
                    onClick={e => e.stopPropagation()}
                  />
                  <span className="control-text">{control.text}</span>
                </label>
              </li>
            );
          })}
          {custom.map(control => (
            <CustomControlItem
              key={control.id}
              control={control}
              scopeKey={scopeKey}
              implemented={!!implementedControls[buildCustomControlKey(scopeKey, control.id)]}
            />
          ))}
        </ul>
      )}

      {isAdding ? (
        <ControlInput
          initialValue=""
          ariaLabel="New custom control"
          placeholder="Describe a control you have in place or plan to add"
          submitLabel="Add"
          onSubmit={text => {
            addCustomControl(scopeKey, text);
            setIsAdding(false);
          }}
          onCancel={() => setIsAdding(false)}
        />
      ) : atCap ? (
        <p className="custom-control-cap">
          {MAX_CUSTOM_CONTROLS_PER_SCOPE} custom controls is the maximum for one threat.
        </p>
      ) : (
        <button
          type="button"
          className="custom-control-add"
          onClick={e => { e.stopPropagation(); setIsAdding(true); }}
        >
          <Plus size={12} strokeWidth={2.5} aria-hidden="true" />
          Add control
        </button>
      )}
    </div>
  );
});

interface CustomControlItemProps {
  control: CustomControl;
  scopeKey: string;
  implemented: boolean;
}

function CustomControlItem({ control, scopeKey, implemented }: CustomControlItemProps) {
  const { setControlImplemented, updateCustomControl, removeCustomControl } = useActions();
  const [isEditing, setIsEditing] = useState(false);
  const key = buildCustomControlKey(scopeKey, control.id);

  if (isEditing) {
    return (
      <li className="control-item custom-control-item editing">
        <ControlInput
          initialValue={control.description}
          ariaLabel="Edit custom control"
          submitLabel="Save"
          onSubmit={text => {
            updateCustomControl(scopeKey, control.id, text);
            setIsEditing(false);
          }}
          onCancel={() => setIsEditing(false)}
        />
      </li>
    );
  }

  return (
    <li className={`control-item custom-control-item ${implemented ? 'implemented' : ''}`}>
      <label className="control-checkbox-label">
        <input
          type="checkbox"
          className="control-checkbox"
          checked={implemented}
          onChange={e => setControlImplemented(key, e.target.checked)}
          onClick={e => e.stopPropagation()}
        />
        <span className="control-text">{control.description}</span>
      </label>
      <span className="custom-control-actions">
        <button
          type="button"
          className="custom-control-icon-button"
          aria-label={`Edit custom control: ${control.description}`}
          title="Edit"
          onClick={e => { e.stopPropagation(); setIsEditing(true); }}
        >
          <Pencil size={12} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="custom-control-icon-button danger"
          aria-label={`Delete custom control: ${control.description}`}
          title="Delete (undo with Ctrl/Cmd+Z)"
          onClick={e => { e.stopPropagation(); removeCustomControl(scopeKey, control.id); }}
        >
          <Trash2 size={12} aria-hidden="true" />
        </button>
      </span>
    </li>
  );
}

interface ControlInputProps {
  initialValue: string;
  ariaLabel: string;
  placeholder?: string;
  submitLabel: string;
  onSubmit: (text: string) => void;
  onCancel: () => void;
}

// Single-line field for adding or rewording a custom control. Enter submits,
// Escape cancels. Blank text can't be submitted; deleting is a separate button.
function ControlInput({ initialValue, ariaLabel, placeholder, submitLabel, onSubmit, onCancel }: ControlInputProps) {
  const [value, setValue] = useState(initialValue);
  const inputRef = useRef<HTMLInputElement>(null);
  const canSubmit = normalizeCustomControlDescription(value) !== null;

  useEffect(() => {
    const input = inputRef.current;
    if (!input) return;
    input.focus();
    // Editing: put the caret at the end rather than selecting everything
    input.setSelectionRange(input.value.length, input.value.length);
  }, []);

  const submit = () => {
    if (canSubmit) onSubmit(value);
  };

  return (
    <div className="custom-control-form" onClick={e => e.stopPropagation()}>
      <input
        ref={inputRef}
        type="text"
        className="custom-control-input"
        value={value}
        maxLength={MAX_CUSTOM_CONTROL_LENGTH}
        placeholder={placeholder}
        aria-label={ariaLabel}
        onChange={e => setValue(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter') {
            e.preventDefault();
            submit();
          } else if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            onCancel();
          }
        }}
      />
      <div className="custom-control-form-row">
        {value.length >= COUNTER_THRESHOLD && (
          <span className="custom-control-counter" aria-live="polite">
            {value.length}/{MAX_CUSTOM_CONTROL_LENGTH}
          </span>
        )}
        <button type="button" className="custom-control-text-button" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="button"
          className="custom-control-text-button primary"
          onClick={submit}
          disabled={!canSubmit}
        >
          {submitLabel}
        </button>
      </div>
    </div>
  );
}
