<?php
namespace SimpleSAML\Module\attributelimit\Auth\Process;

use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;

/**
 * A filter for limiting which attributes are passed on.
 *
 * @author Olav Morken, UNINETT AS.
 * @author Kristóf Bajnok, NIIF
 * @author Tamás Frank, NIIF
 * @author Gyula Szabó, NIIF
 * @author Gyula Szabó, SZTAKI
 * @package SimpleSAMLphp
 */
class AttributeLimit extends \SimpleSAML\Auth\ProcessingFilter {

    /**
     * List of attributes which this filter will allow through.
     */
    private $allowedAttributes = [];

    /**
     * Array of sp attributes arrays which this filter will allow through.
     */
    private $bilateralSPs = [];
    
    /**
     * Array of attribute sps arrays which this filter will allow through.
     */
    private $bilateralAttributes = [];

    /**
     * Whether the 'attributes' option in the metadata takes precedence.
     *
     * @var bool
     */
    private $isDefault = false;


    /**
     * Initialize this filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use
     * @throws Exception If invalid configuration is found.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        foreach ($config as $index => $value) {
            if ($index === 'default') {
                $this->isDefault = (bool)$value;
            } elseif (is_int($index)) {
                if (!is_string($value)) {
                    throw new Exception('AttributeLimit: Invalid attribute name: ' .
                        json_encode($value));
                }
                $this->allowedAttributes[] = $value;
            } elseif ($index === 'bilateralSPs') {
                if (! is_array($value)) {
                    throw new Exception('AttributeLimit: Invalid option bilateralSPs: must be specified in an array: ' . json_encode($index));
                }
                foreach ($value as $valuearray) {
                    if (! is_array($valuearray)) {
                        throw new Exception('AttributeLimit: An invalid value in option bilateralSPs: must be specified in an array: ' . json_encode($value));
                    }
                }
                $this->bilateralSPs = $value;
            } elseif ($index === 'bilateralAttributes') {
                if (! is_array($value)) {
                    throw new Exception('AttributeLimit: Invalid option bilateralAttributes: must be specified in an array: ' . json_encode($index));
                }
                foreach ($value as $valuearray) {
                    if (! is_array($valuearray)) {
                        throw new Exception('AttributeLimit: An invalid value in option bilateralAttributes: must be specified in an array: ' . json_encode($value));
                    }
                }
                $this->bilateralAttributes = $value;
            } elseif (is_string($index)) {
                if (!is_array($value)) {
                    throw new Exception('AttributeLimit: Values for ' . json_encode($index) .
                        ' must be specified in an array.');
                }
                $this->allowedAttributes[$index] = $value;
            } else {
                throw new Exception('AttributeLimit: Invalid option: ' . json_encode($index));
            }
        }
        Logger::debug('AttributeLimit: Allowed attributes at construct: ' . json_encode($this->allowedAttributes));
    }


    /**
     * Get list of allowed from the SP/IdP config.
     *
     * @param array &$request  The current request.
     * @return array|NULL  Array with attribute names, or NULL if no limit is placed.
     */
    private static function getSPIdPAllowed(array &$state)
    {

        Logger::debug('AttributeLimit: state full destination: ' . json_encode($state['Destination']));
        if (array_key_exists('attributes', $state['Destination'])) {
            // SP Config
            Logger::debug('AttributeLimit: state destination: ' . json_encode($state['Destination']['attributes']));
            return $state['Destination']['attributes'];
        } else {
            Logger::debug('AttributeLimit: state destination: NONE');
        }
        if (array_key_exists('attributes', $state['Source'])) {
            // IdP Config
            Logger::debug('AttributeLimit: state source: ' . json_encode($state['Source']['attributes']));
            return $state['Source']['attributes'];
        } else {
            Logger::debug('AttributeLimit: state source: NONE');
        }
        
        return null;
    }


    /**
     * Apply filter to remove attributes.
     *
     * Removes all attributes which aren't one of the allowed attributes.
     *
     * @param array &$request  The current request
     * @throws Exception If invalid configuration is found.
     */
    public function process(&$request): void
    {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        if ($this->isDefault) {
            $allowedAttributes = self::getSPIdPAllowed($request);
            if ($allowedAttributes === null) {
                $allowedAttributes = $this->allowedAttributes;
            }
        } elseif (!empty($this->allowedAttributes)) {
            $allowedAttributes = $this->allowedAttributes;
        } else {
            $allowedAttributes = self::getSPIdPAllowed($request);
            if ($allowedAttributes === null) {
                return; /* No limit on attributes. */
            }
        }

        $attributes =& $request['Attributes'];
        Logger::debug('AttributeLimit: Attributes before filter: ' . json_encode($attributes));

        if (!empty($this->bilateralSPs) || !empty($this->bilateralAttributes)) {
            $entityid = $request['Destination']['entityid'];
        }

        foreach (array_keys($attributes) as $name) {
            Logger::debug('AttributeLimit: check: ' . json_encode($name));
            if (!in_array($name, $allowedAttributes, true)) {
                // the attribute name is not in the array of allowed attributes
                if (array_key_exists($name, $allowedAttributes)) {
                    // but it is an index of the array
                    if (!is_array($allowedAttributes[$name])) {
                        throw new Exception('AttributeLimit: Values for ' . json_encode($name) .
                            ' must be specified in an array.');
                    }
                    $attributes[$name] = array_intersect($attributes[$name], $allowedAttributes[$name]);
                    if (!empty($attributes[$name])) {
                        Logger::debug('AttributeLimit: passed ' . $name);
                        continue;
                    }
                }
                if (!empty($this->bilateralSPs)) {
                    if (array_key_exists($entityid, $this->bilateralSPs)
                            && in_array($name, $this->bilateralSPs[$entityid])
                        ) {
                        continue;
                    }
                }
                if (!empty($this->bilateralAttributes)) {
                    if (array_key_exists($name, $this->bilateralAttributes)
                            && in_array($entityid, $this->bilateralAttributes[$name])
                        ) {
                        continue;
                    }
                }
                Logger::debug('AttributeLimit: drop: ' . json_encode($name));
                unset($attributes[$name]);
            }
        }

        Logger::debug('AttributeLimit: Attributes after filter: ' . json_encode($attributes));
    }
}
