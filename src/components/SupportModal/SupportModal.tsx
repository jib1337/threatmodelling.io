import { useEffect, useRef, useState } from 'react';
import './SupportModal.css';

interface SupportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

declare global {
  interface Window {
    PayPal?: {
      Donation: {
        Button: (config: {
          env: string;
          hosted_button_id: string;
          image: {
            src: string;
            alt: string;
            title: string;
          };
        }) => {
          render: (selector: string) => void;
        };
      };
    };
  }
}

export default function SupportModal({ isOpen, onClose }: SupportModalProps) {
  const [sdkLoaded, setSdkLoaded] = useState(false);
  const [sdkError, setSdkError] = useState(false);
  const buttonContainerRef = useRef<HTMLDivElement>(null);
  const buttonRenderedRef = useRef(false);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  // Load PayPal SDK when modal opens
  useEffect(() => {
    if (!isOpen) return;

    // Check if SDK is already loaded
    if (window.PayPal?.Donation) {
      setSdkLoaded(true);
      return;
    }

    // Check if script is already in DOM
    const existingScript = document.querySelector('script[src*="paypalobjects.com/donate/sdk"]');
    if (existingScript) {
      // Wait for it to load
      const checkLoaded = setInterval(() => {
        if (window.PayPal?.Donation) {
          setSdkLoaded(true);
          clearInterval(checkLoaded);
        }
      }, 100);
      return () => clearInterval(checkLoaded);
    }

    // Load the SDK
    const script = document.createElement('script');
    script.src = 'https://www.paypalobjects.com/donate/sdk/donate-sdk.js';
    script.charset = 'UTF-8';
    script.async = true;

    script.onload = () => {
      setSdkLoaded(true);
    };

    script.onerror = () => {
      setSdkError(true);
    };

    document.body.appendChild(script);
  }, [isOpen]);

  // Render PayPal button when SDK is loaded
  useEffect(() => {
    if (!isOpen || !sdkLoaded || !buttonContainerRef.current || buttonRenderedRef.current) return;

    // Clear any existing content
    buttonContainerRef.current.innerHTML = '<div id="donate-button"></div>';

    // Small delay to ensure DOM is ready
    const timer = setTimeout(() => {
      if (window.PayPal?.Donation) {
        try {
          window.PayPal.Donation.Button({
            env: 'production',
            hosted_button_id: 'UH4PHA8LLKCQS',
            image: {
              src: 'https://www.paypalobjects.com/en_AU/i/btn/btn_donate_LG.gif',
              alt: 'Donate with PayPal button',
              title: 'PayPal - The safer, easier way to pay online!',
            },
          }).render('#donate-button');
          buttonRenderedRef.current = true;
        } catch (err) {
          console.error('Failed to render PayPal button:', err);
          setSdkError(true);
        }
      }
    }, 100);

    return () => clearTimeout(timer);
  }, [isOpen, sdkLoaded]);

  // Reset button rendered state when modal closes
  useEffect(() => {
    if (!isOpen) {
      buttonRenderedRef.current = false;
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="support-modal-overlay" onClick={handleOverlayClick}>
      <div className="support-modal">
        <button className="support-modal-close" onClick={onClose} title="Close">
          &times;
        </button>

        <div className="support-modal-content">
          <h2>Support ThreatModelling.io</h2>

          <p className="support-description">
            ThreatModelling.io is a free tool built to help security professionals
            create better threat models. If you find it useful, please consider supporting
            the project through a donation via PayPal, using the button below.
          </p>

          <div className="support-benefits">
            <h3>Your support helps with:</h3>
            <ul>
              <li>Expanding technology and threat coverage</li>
              <li>Improving features and user experience</li>
              <li>Keeping the service free for everyone</li>
            </ul>
          </div>

          <div className="paypal-button-wrapper">
            {sdkError ? (
              <div className="paypal-error">
                <p>Unable to load PayPal. Please try again later or visit:</p>
                <a
                  href="https://www.paypal.com/donate/?hosted_button_id=UH4PHA8LLKCQS"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="paypal-fallback-link"
                >
                  Donate via PayPal
                </a>
              </div>
            ) : !sdkLoaded ? (
              <div className="paypal-loading">Loading PayPal...</div>
            ) : (
              <div ref={buttonContainerRef} className="paypal-button-container">
                <div id="donate-button"></div>
              </div>
            )}
          </div>
          <p className="support-thanks">
            Thank you for your support!
          </p>
        </div>
      </div>
    </div>
  );
}
