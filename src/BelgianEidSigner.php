<?php

declare(strict_types=1);

namespace Tigress;

use Exception;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use RuntimeException;
use Twig\Error\LoaderError;

/**
 * Belgian eID PDF signer. (PHP version 8.5)
 *
 * Prepares an existing PDF for a detached PAdES signature using Web-eID,
 * and embeds the resulting CMS signature into the PDF.
 *
 * Flow:
 *
 *  1. Tigress/Dompdf creates a normal PDF.
 *  2. Browser obtains the signing certificate through Web-eID.
 *  3. prepare() adds a PDF signature field and returns the hash that
 *     Web-eID must sign.
 *  4. Browser signs the hash using Web-eID.
 *  5. finalize() verifies the signature, builds CMS SignedData and
 *     embeds it into the prepared PDF.
 *
 * Important:
 * - The original PDF is never modified.
 * - The prepared PDF is a temporary/intermediate document.
 * - finalize() writes the signed PDF to a separate output file.
 *
 * @author Rudy Mas <rudy.mas@rudymas.be>
 * @copyright 2026 Rudy Mas (https://www.rudymas.be)
 * @license Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 * @version 2026.09.25.0
 * @package Tigress
 */
class BelgianEidSigner
{
    private const int PDF_SIGNATURE_PLACEHOLDER_BYTES = 16384;

    private const string BYTE_RANGE_MARKER =
        '[0 ########## ########## ##########]';

    /**
     * Get the version of the BelgianEidSigner
     *
     * @return string
     */
    public static function version(): string
    {
        return '2026.09.25';
    }

    /**
     * @throws LoaderError
     */
    public function __construct()
    {
        TWIG->addPath('vendor/tigress/belgian-eid/src/views');
    }

    /**
     * ---------------------------------------------------------------------
     * Public API
     * ---------------------------------------------------------------------
     */

    /**
     * Return information from a Web-eID Base64 DER certificate.
     */
    public function certificateSummary(string $certificate): array
    {
        $pem = $this->base64DerCertificateToPem($certificate);

        $parsed = openssl_x509_parse($pem, false);

        if ($parsed === false) {
            throw new RuntimeException(
                'OpenSSL could not parse the signing certificate.'
            );
        }

        $subject = $parsed['subject'] ?? [];

        return [
            'commonName' => $subject['CN'] ?? null,
            'givenName' => $subject['GN']
                ?? $subject['givenName']
                    ?? null,
            'surname' => $subject['SN']
                ?? $subject['surname']
                    ?? null,
            'serialNumber' => $subject['serialNumber'] ?? null,
            'issuer' => $parsed['issuer']['CN'] ?? null,
            'validFrom' => isset($parsed['validFrom_time_t'])
                ? gmdate(DATE_ATOM, $parsed['validFrom_time_t'])
                : null,
            'validTo' => isset($parsed['validTo_time_t'])
                ? gmdate(DATE_ATOM, $parsed['validTo_time_t'])
                : null,
        ];
    }

    /**
     * Determine the display name of the signer.
     */
    public function signerDisplayName(string $certificate): string
    {
        $summary = $this->certificateSummary($certificate);

        $name = trim(
            implode(
                ' ',
                array_filter(
                    [
                        $summary['givenName'] ?? null,
                        $summary['surname'] ?? null,
                    ],
                    static fn($value) => is_string($value) && $value !== ''
                )
            )
        );

        return $name !== ''
            ? $name
            : (string)(
                $summary['commonName']
                ?? 'Belgian eID signer'
            );
    }

    /**
     * Choose the preferred signing algorithm advertised by Web-eID.
     */
    public function chooseSigningAlgorithm(array $supported): array
    {
        foreach (['SHA-256', 'SHA-384', 'SHA-512'] as $hash) {
            foreach ($supported as $algorithm) {
                if (
                    is_array($algorithm)
                    && ($algorithm['hashFunction'] ?? null) === $hash
                ) {
                    return $algorithm;
                }
            }
        }

        throw new RuntimeException(
            'Card does not advertise a supported SHA-2 signing algorithm.'
        );
    }

    /**
     * Prepare an existing PDF for signing.
     *
     * The original PDF is NOT modified.
     *
     * @return array{
     *     preparedFile:string,
     *     hash:string,
     *     hashFunction:string,
     *     signatureAlgorithm:array,
     *     certificate:string,
     *     signerName:string,
     *     byteRange:array,
     *     contentsPos:int,
     *     contentsHexLength:int,
     *     signedAttributes:string
     * }
     */
    public function prepare(
        string $sourceFile,
        string $preparedFile,
        string $certificate,
        array  $supportedAlgorithms,
        string $fieldName = 'Signature',
        ?array $position = null
    ): array
    {
        if (!is_file($sourceFile)) {
            throw new InvalidArgumentException(
                'PDF file does not exist: ' . $sourceFile
            );
        }

        $pdf = file_get_contents($sourceFile);

        if ($pdf === false) {
            throw new RuntimeException(
                'Unable to read PDF file: ' . $sourceFile
            );
        }

        if (!str_starts_with($pdf, '%PDF-')) {
            throw new InvalidArgumentException(
                'The supplied file is not a PDF document.'
            );
        }

        $signatureAlgorithm =
            $this->chooseSigningAlgorithm($supportedAlgorithms);

        $hashFunction =
            (string)$signatureAlgorithm['hashFunction'];

        $hashName = $this->hashNameForPhp($hashFunction);

        $signerName =
            $this->signerDisplayName($certificate);

        /*
         * Add the PDF signature dictionary using an incremental update.
         */
        $prepared = $this->addSignaturePlaceholder(
            $pdf,
            $signerName,
            $fieldName,
            $position
        );

        $preparedPdf = $prepared['pdf'];

        /*
         * Determine the actual bytes covered by /ByteRange.
         */
        $signedPdfBytes = $this->getPdfByteRangeBytes(
            $preparedPdf,
            $prepared['byte_range']
        );

        /*
         * Digest of the PDF itself.
         */
        $documentDigest = hash(
            $hashName,
            $signedPdfBytes,
            true
        );

        $certificateDer = base64_decode(
            $certificate,
            true
        );

        if ($certificateDer === false) {
            throw new InvalidArgumentException(
                'Invalid Base64 certificate.'
            );
        }

        /*
         * Create the CMS SignedAttributes.
         *
         * Web-eID signs the hash of these attributes,
         * not the PDF digest directly.
         */
        $signedAttributes =
            $this->buildPadesSignedAttributes(
                $documentDigest,
                $certificateDer,
                $hashFunction
            );

        $hashToSign = hash(
            $hashName,
            $signedAttributes,
            true
        );

        $directory = dirname($preparedFile);

        if (
            !is_dir($directory)
            && !mkdir($directory, 0770, true)
            && !is_dir($directory)
        ) {
            throw new RuntimeException(
                'Unable to create directory: ' . $directory
            );
        }

        if (
            file_put_contents(
                $preparedFile,
                $preparedPdf,
                LOCK_EX
            ) === false
        ) {
            throw new RuntimeException(
                'Unable to write prepared PDF.'
            );
        }

        return [
            'preparedFile' => $preparedFile,

            /*
             * Web-eID expects the digest in Base64.
             */
            'hash' => base64_encode($hashToSign),
            'hashFunction' => $hashFunction,
            'signatureAlgorithm' => $signatureAlgorithm,

            'certificate' => $certificate,
            'signerName' => $signerName,

            /*
             * These values are server-side signing state.
             * Do NOT trust copies returned by the browser.
             */
            'byteRange' => $prepared['byte_range'],
            'contentsPos' => $prepared['contents_pos'],
            'contentsHexLength' => $prepared['contents_hex_length'],

            /*
             * Binary DER.
             * Store this server-side, for example in the session/database.
             */
            'signedAttributes' => base64_encode($signedAttributes),
        ];
    }

    /**
     * Finalize a prepared PDF after Web-eID returned the signature.
     */
    public function finalize(
        string $preparedFile,
        string $outputFile,
        string $certificate,
        string $signatureBase64,
        array  $signatureAlgorithm,
        array  $byteRange,
        int    $contentsPos,
        int    $contentsHexLength,
        string $signedAttributesBase64
    ): void
    {
        if (!is_file($preparedFile)) {
            throw new InvalidArgumentException(
                'Prepared PDF does not exist.'
            );
        }

        $preparedPdf = file_get_contents($preparedFile);

        if ($preparedPdf === false) {
            throw new RuntimeException(
                'Unable to read prepared PDF.'
            );
        }

        $signedAttributes = base64_decode(
            $signedAttributesBase64,
            true
        );

        if ($signedAttributes === false) {
            throw new InvalidArgumentException(
                'Invalid signed attributes.'
            );
        }

        /*
         * First verify that the signature returned by Web-eID
         * really belongs to these signed attributes.
         */
        if (
            !$this->verifyWebEidSignatureOverSignedAttributes(
                $signedAttributes,
                $certificate,
                $signatureBase64,
                $signatureAlgorithm
            )
        ) {
            throw new RuntimeException(
                'The Web-eID signature could not be verified.'
            );
        }

        $certificateDer = base64_decode(
            $certificate,
            true
        );

        if ($certificateDer === false) {
            throw new InvalidArgumentException(
                'Invalid Base64 certificate.'
            );
        }

        $signatureValue =
            $this->webEidSignatureForCms(
                $signatureBase64,
                $signatureAlgorithm
            );

        /*
         * Build detached CMS SignedData.
         */
        $cmsDer = $this->buildDetachedCms(
            $certificateDer,
            $signedAttributes,
            $signatureValue,
            $signatureAlgorithm
        );

        /*
         * Insert CMS into the reserved /Contents area.
         */
        $signedPdf = $this->embedCmsIntoPdf(
            $preparedPdf,
            $contentsPos,
            $contentsHexLength,
            $cmsDer
        );

        /*
         * Optional additional sanity check using OpenSSL.
         */
        $verified = $this->verifyFinalPdfCmsWithOpenSsl(
            $signedPdf,
            $byteRange,
            $cmsDer
        );

        if ($verified === false) {
            throw new RuntimeException(
                'Final CMS signature verification failed.'
            );
        }

        $directory = dirname($outputFile);

        if (
            !is_dir($directory)
            && !mkdir($directory, 0770, true)
            && !is_dir($directory)
        ) {
            throw new RuntimeException(
                'Unable to create output directory.'
            );
        }

        if (
            file_put_contents(
                $outputFile,
                $signedPdf,
                LOCK_EX
            ) === false
        ) {
            throw new RuntimeException(
                'Unable to write signed PDF.'
            );
        }
    }

    /**
     * Create a digital signature position for a PDF document
     *
     * @param int $width
     * @param int $height
     * @param int $top
     * @param int $bottom
     * @param int $left
     * @param int $right
     * @param string $pageFormat
     * @param string $pageOrientation
     * @param string $place
     * @param int|string $page
     * @return array
     * @throws Exception
     */
    #[ArrayShape(['page' => "int|string", 'x1' => "float|int", 'y1' => "float|int", 'x2' => "float|int", 'y2' => "float|int"])]
    public function signaturePosition(
        int        $width,
        int        $height,
        int        $top = 0,
        int        $bottom = 0,
        int        $left = 0,
        int        $right = 0,
        string     $pageFormat = 'A4',
        string     $pageOrientation = 'portrait',
        string     $place = 'bottom-right',
        int|string $page = 'last',
    ): array
    {
        switch ($pageFormat) {
            case 'A3':
                $pageWidth = 841.89; // points
                $pageHeight = 1190.55; // points
                break;
            case 'A4':
                $pageWidth = 595.28; // points
                $pageHeight = 841.89; // points
                break;
            case 'A5':
                $pageWidth = 419.53; // points
                $pageHeight = 595.28; // points
                break;
            case 'Letter':
                $pageWidth = 612; // points
                $pageHeight = 792; // points
                break;
            default:
                throw new Exception("Unsupported page format: {$pageFormat}");
        }

        if ($pageOrientation === 'landscape') {
            [$pageWidth, $pageHeight] = [$pageHeight, $pageWidth];
        }

        $widthPt = $this->pxToPt($width);
        $heightPt = $this->pxToPt($height);

        $topPt = $this->pxToPt($top);
        $bottomPt = $this->pxToPt($bottom);
        $leftPt = $this->pxToPt($left);
        $rightPt = $this->pxToPt($right);

        switch ($place) {
            case 'top-left':
                $x1 = $leftPt;
                $y1 = $pageHeight - $topPt - $heightPt;
                $x2 = $leftPt + $widthPt;
                $y2 = $pageHeight - $topPt;
                break;
            case 'top-right':
                $x1 = $pageWidth - $rightPt - $widthPt;
                $y1 = $pageHeight - $topPt - $heightPt;
                $x2 = $pageWidth - $rightPt;
                $y2 = $pageHeight - $topPt;
                break;
            case 'bottom-left':
                $x1 = $leftPt;
                $y1 = $bottomPt;
                $x2 = $leftPt + $widthPt;
                $y2 = $bottomPt + $heightPt;
                break;
            case 'bottom-right':
                $x1 = $pageWidth - $rightPt - $widthPt;
                $y1 = $bottomPt;
                $x2 = $pageWidth - $rightPt;
                $y2 = $bottomPt + $heightPt;
                break;
            default:
                throw new Exception("Unsupported signature place: {$place}");
        }

        return [
            'page' => $page,
            'x1' => $x1 ?? 0,
            'y1' => $y1 ?? 0,
            'x2' => $x2 ?? 0,
            'y2' => $y2 ?? 0,
        ];
    }

    /**
     * Convert pixels to points
     *
     * @param float $px
     * @return float
     */
    public function pxToPt(float $px): float
    {
        return $px * 72 / 96; // 1 inch = 96 px, 1 inch = 72 pt
    }

    /**
     * ---------------------------------------------------------------------
     * PDF handling
     * ---------------------------------------------------------------------
     */

    private function addSignaturePlaceholder(
        string $pdf,
        string $signerName,
        string $fieldName,
        ?array $position = null
    ): array
    {
        $startXref = $this->findStartXref($pdf);
        $trailer = $this->findTrailer($pdf);

        /*
         * Find PDF catalog.
         */
        if (!preg_match(
            '/\/Root\s+(\d+)\s+(\d+)\s+R/',
            $trailer,
            $rootMatch
        )) {
            throw new RuntimeException(
                'Unable to locate PDF catalog.'
            );
        }

        if (!preg_match(
            '/\/Size\s+(\d+)/',
            $trailer,
            $sizeMatch
        )) {
            throw new RuntimeException(
                'Unable to determine PDF object count.'
            );
        }

        $rootObjectNumber = (int)$rootMatch[1];
        $rootGeneration = (int)$rootMatch[2];
        $size = (int)$sizeMatch[1];

        $catalog = $this->findObject(
            $pdf,
            $rootObjectNumber,
            $rootGeneration
        );

        /*
         * We may need a page object when a visible signature
         * position was supplied.
         */
        $pageObjectNumber = null;
        $pageGeneration = 0;
        $pageObject = null;

        if ($position !== null) {
            foreach (['x1', 'y1', 'x2', 'y2'] as $coordinate) {
                if (
                    !array_key_exists($coordinate, $position)
                    || !is_numeric($position[$coordinate])
                ) {
                    throw new InvalidArgumentException(
                        'Signature position requires numeric '
                        . $coordinate . '.'
                    );
                }
            }

            $page = $position['page'] ?? 'last';

            [
                $pageObjectNumber,
                $pageGeneration,
                $pageObject
            ] = $this->findPageObject(
                $pdf,
                $page
            );
        }

        /*
         * ------------------------------------------------------------------
         * Allocate objects.
         * ------------------------------------------------------------------
         */

        $nextObject = $size;

        $objects = [];

        /*
         * Existing AcroForm?
         */
        if (preg_match(
            '/\/AcroForm\s+(\d+)\s+(\d+)\s+R/',
            $catalog,
            $acroMatch
        )) {
            /*
             * A previous signature already created an AcroForm.
             */
            $acroFormObject = (int)$acroMatch[1];
            $acroFormGeneration = (int)$acroMatch[2];

            $acroForm = $this->findObject(
                $pdf,
                $acroFormObject,
                $acroFormGeneration
            );

            $signatureFieldObject = $nextObject++;
            $signatureObject = $nextObject++;

            $acroForm = $this->appendFieldToAcroForm(
                $acroForm,
                $signatureFieldObject
            );

            /*
             * Rewrite the AcroForm in this incremental revision.
             */
            $objects[$acroFormObject] = [
                'generation' => $acroFormGeneration,
                'content' => $acroForm,
            ];
        } else {
            /*
             * First signature.
             *
             * Create an AcroForm and update the catalog.
             */
            $acroFormObject = $nextObject++;
            $signatureFieldObject = $nextObject++;
            $signatureObject = $nextObject++;

            $catalog = $this->appendDictionaryEntry(
                $catalog,
                '/AcroForm ' . $acroFormObject . ' 0 R'
            );

            $objects[$rootObjectNumber] = [
                'generation' => $rootGeneration,
                'content' => $catalog,
            ];

            $objects[$acroFormObject] = [
                'generation' => 0,
                'content' =>
                    '<< '
                    . '/Fields ['
                    . $signatureFieldObject
                    . ' 0 R] '
                    . '/SigFlags 3 '
                    . '>>',
            ];
        }

        /*
         * ------------------------------------------------------------------
         * Signature field / widget.
         * ------------------------------------------------------------------
         */

        $safeFieldName = $this->escapePdfText(
            $fieldName
        );

        $safeSignerName = $this->escapePdfText(
            $signerName
        );

        if ($position !== null) {
            /*
             * Visible widget.
             *
             * The signature field itself is also the Widget annotation.
             */
            $x1 = (float)$position['x1'];
            $y1 = (float)$position['y1'];
            $x2 = (float)$position['x2'];
            $y2 = (float)$position['y2'];

            if (
                $x2 <= $x1
                || $y2 <= $y1
            ) {
                throw new InvalidArgumentException(
                    'Invalid signature rectangle.'
                );
            }

            $rect = sprintf(
                '[%.2F %.2F %.2F %.2F]',
                $x1,
                $y1,
                $x2,
                $y2
            );

            $objects[$signatureFieldObject] = [
                'generation' => 0,
                'content' =>
                    '<< '
                    . '/Type /Annot '
                    . '/Subtype /Widget '
                    . '/FT /Sig '
                    . '/T (' . $safeFieldName . ') '
                    . '/Rect ' . $rect . ' '
                    . '/P '
                    . $pageObjectNumber
                    . ' '
                    . $pageGeneration
                    . ' R '
                    . '/V '
                    . $signatureObject
                    . ' 0 R '
                    . '/F 4 '
                    . '>>',
            ];

            /*
             * Add Widget annotation to the page.
             */
            $pageObject = $this->appendAnnotationToPage(
                $pageObject,
                $signatureFieldObject
            );

            $objects[$pageObjectNumber] = [
                'generation' => $pageGeneration,
                'content' => $pageObject,
            ];
        } else {
            /*
             * Invisible signature field.
             */
            $objects[$signatureFieldObject] = [
                'generation' => 0,
                'content' =>
                    '<< '
                    . '/FT /Sig '
                    . '/T (' . $safeFieldName . ') '
                    . '/V '
                    . $signatureObject
                    . ' 0 R '
                    . '>>',
            ];
        }

        /*
         * ------------------------------------------------------------------
         * Signature dictionary.
         * ------------------------------------------------------------------
         */

        $contentsHexLength =
            self::PDF_SIGNATURE_PLACEHOLDER_BYTES * 2;

        $contentsMarker =
            '<'
            . str_repeat('0', $contentsHexLength)
            . '>';

        $pdfDate =
            'D:' . gmdate('YmdHis') . 'Z';

        $objects[$signatureObject] = [
            'generation' => 0,
            'content' =>
                '<< '
                . '/Type /Sig '
                . '/Filter /Adobe.PPKLite '
                . '/SubFilter /ETSI.CAdES.detached '
                . '/ByteRange '
                . self::BYTE_RANGE_MARKER
                . ' '
                . '/Contents '
                . $contentsMarker
                . ' '
                . '/M (' . $pdfDate . ') '
                . '/Name (' . $safeSignerName . ') '
                . '/Reason '
                . '(Document approval using Belgian eID) '
                . '>>',
        ];

        /*
         * ------------------------------------------------------------------
         * Incremental PDF revision.
         * ------------------------------------------------------------------
         */

        /*
         * Sort by object number. This makes the generated PDF easier
         * to inspect and simplifies xref generation.
         */
        ksort(
            $objects,
            SORT_NUMERIC
        );

        $increment = "\n";
        $offsets = [];

        foreach ($objects as $number => $object) {
            $offsets[$number] =
                strlen($pdf)
                + strlen($increment);

            $increment .=
                $number
                . ' '
                . $object['generation']
                . " obj\n"
                . $object['content']
                . "\nendobj\n";
        }

        /*
         * ------------------------------------------------------------------
         * Cross-reference table.
         * ------------------------------------------------------------------
         */

        $xrefOffset =
            strlen($pdf)
            + strlen($increment);

        $increment .= "xref\n";

        $xrefObjects =
            array_keys($objects);

        /*
         * Split into consecutive groups.
         *
         * Example:
         *
         * 1
         * 7
         * 8
         * 9
         *
         * becomes:
         *
         * xref
         * 1 1
         * ...
         * 7 3
         * ...
         */
        $groups = [];

        foreach ($xrefObjects as $objectNumber) {
            if ($groups === []) {
                $groups[] = [$objectNumber];
                continue;
            }

            $lastGroupIndex =
                count($groups) - 1;

            $lastObject =
                $groups[$lastGroupIndex][count($groups[$lastGroupIndex]) - 1];

            if ($objectNumber === $lastObject + 1) {
                $groups[$lastGroupIndex][] =
                    $objectNumber;
            } else {
                $groups[] =
                    [$objectNumber];
            }
        }

        foreach ($groups as $group) {
            $increment .=
                $group[0]
                . ' '
                . count($group)
                . "\n";

            foreach ($group as $number) {
                $increment .= sprintf(
                    "%010d %05d n \n",
                    $offsets[$number],
                    $objects[$number]['generation']
                );
            }
        }

        /*
         * /Size must be one higher than the highest object number
         * that exists in the complete PDF.
         */
        $highestObject =
            max(
                $size - 1,
                ...array_keys($objects)
            );

        $newSize =
            $highestObject + 1;

        /*
         * Trailer for this revision.
         *
         * /Prev points to the previous xref table.
         */
        $increment .=
            "trailer\n"
            . "<< "
            . "/Size " . $newSize . ' '
            . "/Root "
            . $rootObjectNumber
            . ' '
            . $rootGeneration
            . ' R '
            . "/Prev "
            . $startXref
            . ' '
            . ">>\n"
            . "startxref\n"
            . $xrefOffset
            . "\n%%EOF\n";

        $preparedPdf =
            $pdf
            . $increment;

        /*
         * ------------------------------------------------------------------
         * ByteRange
         * ------------------------------------------------------------------
         *
         * Always use strrpos().
         *
         * When this is signature #2, the PDF already contains the
         * /Contents and /ByteRange belonging to signature #1.
         */

        $byteRangePos =
            strrpos(
                $preparedPdf,
                self::BYTE_RANGE_MARKER
            );

        $contentsPos =
            strrpos(
                $preparedPdf,
                $contentsMarker
            );

        if (
            $byteRangePos === false
            || $contentsPos === false
        ) {
            throw new RuntimeException(
                'Unable to locate PDF signature placeholders.'
            );
        }

        /*
         * The hexadecimal /Contents value including < and >
         * is excluded from the signed data.
         */
        $range1Length =
            $contentsPos;

        $range2Offset =
            $contentsPos
            + strlen($contentsMarker);

        $range2Length =
            strlen($preparedPdf)
            - $range2Offset;

        foreach (
            [
                $range1Length,
                $range2Offset,
                $range2Length,
            ] as $value
        ) {
            if ($value > 9_999_999_999) {
                throw new RuntimeException(
                    'PDF is too large for ByteRange formatter.'
                );
            }
        }

        $byteRange = sprintf(
            '[0 %10d %10d %10d]',
            $range1Length,
            $range2Offset,
            $range2Length
        );

        if (
            strlen($byteRange)
            !== strlen(self::BYTE_RANGE_MARKER)
        ) {
            throw new RuntimeException(
                'ByteRange placeholder size mismatch.'
            );
        }

        $preparedPdf = substr_replace(
            $preparedPdf,
            $byteRange,
            $byteRangePos,
            strlen(self::BYTE_RANGE_MARKER)
        );

        return [
            'pdf' => $preparedPdf,

            'contents_pos' =>
                $contentsPos,

            'contents_hex_length' =>
                $contentsHexLength,

            'byte_range' => [
                0,
                $range1Length,
                $range2Offset,
                $range2Length,
            ],

            'field_name' =>
                $fieldName,

            'page_object' =>
                $pageObjectNumber,
        ];
    }

    private function appendAnnotationToPage(
        string $pageObject,
        int    $annotationObject
    ): string
    {
        /*
         * Page already has an /Annots array.
         */
        if (preg_match(
            '/\/Annots\s*\[(.*?)\]/s',
            $pageObject,
            $matches,
            PREG_OFFSET_CAPTURE
        )) {
            $fullMatch =
                $matches[0][0];

            $position =
                $matches[0][1];

            $existing =
                trim($matches[1][0]);

            $replacement =
                '/Annots [';

            if ($existing !== '') {
                $replacement .=
                    $existing
                    . ' ';
            }

            $replacement .=
                $annotationObject
                . ' 0 R]';

            return substr_replace(
                $pageObject,
                $replacement,
                $position,
                strlen($fullMatch)
            );
        }

        /*
         * No /Annots yet.
         */
        return $this->appendDictionaryEntry(
            $pageObject,
            '/Annots ['
            . $annotationObject
            . ' 0 R]'
        );
    }

    private function findStartXref(string $pdf): int
    {
        $position = strrpos($pdf, 'startxref');

        if ($position === false) {
            throw new RuntimeException(
                'Unable to locate startxref in PDF.'
            );
        }

        $part = substr($pdf, $position);

        if (!preg_match(
            '/startxref\s+(\d+)/',
            $part,
            $matches
        )) {
            throw new RuntimeException(
                'Unable to read startxref offset.'
            );
        }

        return (int)$matches[1];
    }

    private function findPageObject(
        string $pdf,
        int|string $page = 'last'
    ): array
    {
        if (!preg_match_all(
            '/(\d+)\s+(\d+)\s+obj\s*(.*?)\s*endobj/s',
            $pdf,
            $matches,
            PREG_SET_ORDER
        )) {
            throw new RuntimeException(
                'Unable to locate PDF objects.'
            );
        }

        /*
         * A PDF using incremental updates can contain an older
         * and a newer version of the same page object.
         *
         * Keep the last occurrence of every page object number.
         */
        $pages = [];

        foreach ($matches as $match) {
            $content = $match[3];

            /*
             * Match /Type /Page, but not /Type /Pages.
             */
            if (!preg_match(
                '/\/Type\s*\/Page\b/',
                $content
            )) {
                continue;
            }

            $objectNumber = (int)$match[1];

            $pages[$objectNumber] = [
                'number' => $objectNumber,
                'generation' => (int)$match[2],
                'content' => $content,
            ];
        }

        $pages = array_values($pages);

        if ($pages === []) {
            throw new RuntimeException(
                'PDF contains no pages.'
            );
        }

        if ($page === 'last') {
            $selected = $pages[count($pages) - 1];
        } else {
            $pageNumber = (int)$page;

            if (
                $pageNumber < 1
                || $pageNumber > count($pages)
            ) {
                throw new InvalidArgumentException(
                    sprintf(
                        'Invalid PDF page number %d. Document contains %d pages.',
                        $pageNumber,
                        count($pages)
                    )
                );
            }

            $selected = $pages[$pageNumber - 1];
        }

        return [
            $selected['number'],
            $selected['generation'],
            $selected['content'],
        ];
    }

    private function appendFieldToAcroForm(
        string $acroForm,
        int    $fieldObject
    ): string
    {
        /*
         * Find the existing /Fields array.
         */
        if (!preg_match(
            '/\/Fields\s*\[(.*?)\]/s',
            $acroForm,
            $matches,
            PREG_OFFSET_CAPTURE
        )) {
            throw new RuntimeException(
                'Existing AcroForm does not contain a /Fields array.'
            );
        }

        $fullMatch =
            $matches[0][0];

        $position =
            $matches[0][1];

        $existingFields =
            trim(
                $matches[1][0]
            );

        $newFields =
            '/Fields [';

        if ($existingFields !== '') {
            $newFields .=
                $existingFields
                . ' ';
        }

        $newFields .=
            $fieldObject
            . ' 0 R]';

        return substr_replace(
            $acroForm,
            $newFields,
            $position,
            strlen($fullMatch)
        );
    }

    private function findTrailer(string $pdf): string
    {
        if (
            !preg_match_all(
                '/trailer\s*(<<.*?>>)\s*startxref/sU',
                $pdf,
                $matches
            )
        ) {
            throw new RuntimeException(
                'Unable to locate PDF trailer.'
            );
        }

        return (string)end($matches[1]);
    }

    private function findObject(
        string $pdf,
        int    $objectNumber,
        int    $generation
    ): string
    {
        $pattern =
            '/(?:^|\R)'
            . preg_quote(
                $objectNumber
                . ' '
                . $generation
                . ' obj',
                '/'
            )
            . '\s*(.*?)\s*endobj/s';

        if (
            !preg_match_all(
                $pattern,
                $pdf,
                $matches
            )
        ) {
            throw new RuntimeException(
                sprintf(
                    'Unable to locate PDF object %d %d.',
                    $objectNumber,
                    $generation
                )
            );
        }

        return (string)end($matches[1]);
    }

    private function appendDictionaryEntry(
        string $dictionary,
        string $entry
    ): string
    {
        $position = strrpos(
            $dictionary,
            '>>'
        );

        if ($position === false) {
            throw new RuntimeException(
                'Invalid PDF catalog dictionary.'
            );
        }

        return substr(
                $dictionary,
                0,
                $position
            )
            . ' '
            . $entry
            . ' '
            . substr(
                $dictionary,
                $position
            );
    }

    private function getPdfByteRangeBytes(
        string $pdf,
        array  $range
    ): string
    {
        [
            $offset1,
            $length1,
            $offset2,
            $length2
        ] = $range;

        return
            substr(
                $pdf,
                $offset1,
                $length1
            )
            .
            substr(
                $pdf,
                $offset2,
                $length2
            );
    }

    private function embedCmsIntoPdf(
        string $preparedPdf,
        int    $contentsPos,
        int    $contentsHexLength,
        string $cmsDer
    ): string
    {
        $hex =
            strtoupper(
                bin2hex($cmsDer)
            );

        if (
            strlen($hex)
            > $contentsHexLength
        ) {
            throw new RuntimeException(
                sprintf(
                    'CMS signature is too large for PDF placeholder '
                    . '(%d > %d hex chars).',
                    strlen($hex),
                    $contentsHexLength
                )
            );
        }

        $hex = str_pad(
            $hex,
            $contentsHexLength,
            '0'
        );

        /*
         * +1 skips the opening "<".
         */
        return substr_replace(
            $preparedPdf,
            $hex,
            $contentsPos + 1,
            $contentsHexLength
        );
    }

    private function escapePdfText(string $text): string
    {
        $text =
            iconv(
                'UTF-8',
                'ASCII//TRANSLIT//IGNORE',
                $text
            ) ?: $text;

        return str_replace(
            [
                '\\',
                '(',
                ')',
                "\r",
                "\n",
            ],
            [
                '\\\\',
                '\\(',
                '\\)',
                ' ',
                ' ',
            ],
            $text
        );
    }

    /**
     * ---------------------------------------------------------------------
     * Certificate / crypto helpers
     * ---------------------------------------------------------------------
     */

    private function base64DerCertificateToPem(
        string $certificate
    ): string
    {
        $der = base64_decode(
            $certificate,
            true
        );

        if (
            $der === false
            || $der === ''
        ) {
            throw new InvalidArgumentException(
                'Invalid Base64 certificate.'
            );
        }

        return
            "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(
                base64_encode($der),
                64,
                "\n"
            )
            . "-----END CERTIFICATE-----\n";
    }

    private function hashNameForPhp(
        string $webEidHash
    ): string
    {
        return match ($webEidHash) {
            'SHA-256' => 'sha256',
            'SHA-384' => 'sha384',
            'SHA-512' => 'sha512',

            default =>
            throw new InvalidArgumentException(
                'Unsupported hash function: '
                . $webEidHash
            ),
        };
    }

    /**
     * ---------------------------------------------------------------------
     * ASN.1 / DER
     * ---------------------------------------------------------------------
     */

    private function asn1Length(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $encoded = '';

        while ($length > 0) {
            $encoded =
                chr($length & 0xff)
                . $encoded;

            $length >>= 8;
        }

        return
            chr(0x80 | strlen($encoded))
            . $encoded;
    }

    private function der(
        int    $tag,
        string $value
    ): string
    {
        return
            chr($tag)
            . $this->asn1Length(
                strlen($value)
            )
            . $value;
    }

    private function derSequence(
        string ...$parts
    ): string
    {
        return $this->der(
            0x30,
            implode('', $parts)
        );
    }

    private function derSet(
        string ...$parts
    ): string
    {
        sort(
            $parts,
            SORT_STRING
        );

        return $this->der(
            0x31,
            implode('', $parts)
        );
    }

    private function derInteger(
        int|string $value
    ): string
    {
        if (is_int($value)) {
            if ($value < 0) {
                throw new InvalidArgumentException(
                    'Negative DER integers are not supported.'
                );
            }

            $bytes = '';

            do {
                $bytes =
                    chr($value & 0xff)
                    . $bytes;

                $value >>= 8;
            } while ($value > 0);
        } else {
            $bytes =
                ltrim(
                    $value,
                    "\x00"
                );

            if ($bytes === '') {
                $bytes = "\x00";
            }
        }

        if (
            (ord($bytes[0]) & 0x80)
            !== 0
        ) {
            $bytes =
                "\x00"
                . $bytes;
        }

        return $this->der(
            0x02,
            $bytes
        );
    }

    private function derOctetString(
        string $value
    ): string
    {
        return $this->der(
            0x04,
            $value
        );
    }

    private function derNull(): string
    {
        return "\x05\x00";
    }

    private function derOid(
        string $oid
    ): string
    {
        $parts =
            array_map(
                'intval',
                explode('.', $oid)
            );

        if (count($parts) < 2) {
            throw new InvalidArgumentException(
                'Invalid OID.'
            );
        }

        $out =
            chr(
                ($parts[0] * 40)
                + $parts[1]
            );

        foreach (
            array_slice($parts, 2)
            as $part
        ) {
            $encoded =
                chr($part & 0x7f);

            $part >>= 7;

            while ($part > 0) {
                $encoded =
                    chr(
                        0x80
                        | ($part & 0x7f)
                    )
                    . $encoded;

                $part >>= 7;
            }

            $out .= $encoded;
        }

        return $this->der(
            0x06,
            $out
        );
    }

    private function asn1ReadTlv(
        string $data,
        int    $offset = 0
    ): array
    {
        $start = $offset;

        if (!isset($data[$offset])) {
            throw new RuntimeException(
                'Unexpected end of ASN.1 data.'
            );
        }

        $tag =
            ord(
                $data[$offset++]
            );

        if (!isset($data[$offset])) {
            throw new RuntimeException(
                'Unexpected end of ASN.1 length.'
            );
        }

        $firstLength =
            ord(
                $data[$offset++]
            );

        if (
            ($firstLength & 0x80)
            === 0
        ) {
            $length = $firstLength;
        } else {
            $count =
                $firstLength & 0x7f;

            if (
                $count === 0
                || $count > 4
            ) {
                throw new RuntimeException(
                    'Unsupported ASN.1 length encoding.'
                );
            }

            $length = 0;

            for (
                $i = 0;
                $i < $count;
                $i++
            ) {
                if (!isset($data[$offset])) {
                    throw new RuntimeException(
                        'Unexpected end of ASN.1 long length.'
                    );
                }

                $length =
                    ($length << 8)
                    | ord(
                        $data[$offset++]
                    );
            }
        }

        $valueOffset =
            $offset;

        $total =
            ($valueOffset - $start)
            + $length;

        if (
            $start + $total
            > strlen($data)
        ) {
            throw new RuntimeException(
                'ASN.1 object extends past input.'
            );
        }

        return [
            'tag' => $tag,
            'length' => $length,
            'header_length' => $valueOffset - $start,
            'total_length' => $total,
            'value_offset' => $valueOffset,
            'value' => substr(
                $data,
                $valueOffset,
                $length
            ),
            'raw' => substr(
                $data,
                $start,
                $total
            ),
        ];
    }

    private function certificateIssuerAndSerial(
        string $certificateDer
    ): array
    {
        $certificate =
            $this->asn1ReadTlv(
                $certificateDer
            );

        if (
            $certificate['tag']
            !== 0x30
        ) {
            throw new RuntimeException(
                'Certificate is not an ASN.1 SEQUENCE.'
            );
        }

        $tbs =
            $this->asn1ReadTlv(
                $certificate['value']
            );

        if ($tbs['tag'] !== 0x30) {
            throw new RuntimeException(
                'Invalid TBSCertificate.'
            );
        }

        $value =
            $tbs['value'];

        $offset = 0;

        $first =
            $this->asn1ReadTlv(
                $value,
                $offset
            );

        /*
         * [0] EXPLICIT version
         */
        if ($first['tag'] === 0xA0) {
            $offset +=
                $first['total_length'];
        }

        $serial =
            $this->asn1ReadTlv(
                $value,
                $offset
            );

        if ($serial['tag'] !== 0x02) {
            throw new RuntimeException(
                'Could not locate certificate serial number.'
            );
        }

        $offset +=
            $serial['total_length'];

        /*
         * Skip signature algorithm.
         */
        $signatureAlgorithm =
            $this->asn1ReadTlv(
                $value,
                $offset
            );

        $offset +=
            $signatureAlgorithm['total_length'];

        $issuer =
            $this->asn1ReadTlv(
                $value,
                $offset
            );

        if ($issuer['tag'] !== 0x30) {
            throw new RuntimeException(
                'Could not locate certificate issuer.'
            );
        }

        return [
            'serial_raw' =>
                $serial['value'],

            'issuer_raw' =>
                $issuer['raw'],
        ];
    }

    private function algorithmIdentifier(
        string $oid,
        bool   $withNull = false
    ): string
    {
        return $this->derSequence(
            $this->derOid($oid),
            $withNull
                ? $this->derNull()
                : ''
        );
    }

    private function digestOid(
        string $hashFunction
    ): string
    {
        return match ($hashFunction) {
            'SHA-256' =>
            '2.16.840.1.101.3.4.2.1',

            'SHA-384' =>
            '2.16.840.1.101.3.4.2.2',

            'SHA-512' =>
            '2.16.840.1.101.3.4.2.3',

            default =>
            throw new InvalidArgumentException(
                'Unsupported digest algorithm.'
            ),
        };
    }

    private function signatureOid(
        array $signatureAlgorithm
    ): string
    {
        $crypto =
            strtoupper(
                (string)(
                    $signatureAlgorithm['cryptoAlgorithm'] ?? ''
                )
            );

        $hash =
            (string)(
                $signatureAlgorithm['hashFunction'] ?? ''
            );

        if (
            $crypto === 'ECC'
            || $crypto === 'EC'
        ) {
            return match ($hash) {
                'SHA-256' =>
                '1.2.840.10045.4.3.2',

                'SHA-384' =>
                '1.2.840.10045.4.3.3',

                'SHA-512' =>
                '1.2.840.10045.4.3.4',

                default =>
                throw new InvalidArgumentException(
                    'Unsupported ECDSA hash algorithm.'
                ),
            };
        }

        if ($crypto === 'RSA') {
            return match ($hash) {
                'SHA-256' =>
                '1.2.840.113549.1.1.11',

                'SHA-384' =>
                '1.2.840.113549.1.1.12',

                'SHA-512' =>
                '1.2.840.113549.1.1.13',

                default =>
                throw new InvalidArgumentException(
                    'Unsupported RSA hash algorithm.'
                ),
            };
        }

        throw new InvalidArgumentException(
            'Unsupported crypto algorithm returned by Web-eID: '
            . $crypto
        );
    }

    /**
     * ---------------------------------------------------------------------
     * PAdES / CMS
     * ---------------------------------------------------------------------
     */

    private function buildPadesSignedAttributes(
        string $documentDigest,
        string $certificateDer,
        string $hashFunction
    ): string
    {
        /*
         * ContentType = id-data.
         */
        $contentType =
            $this->derSequence(
                $this->derOid(
                    '1.2.840.113549.1.9.3'
                ),
                $this->derSet(
                    $this->derOid(
                        '1.2.840.113549.1.7.1'
                    )
                )
            );

        /*
         * MessageDigest = digest of PDF ByteRange.
         */
        $messageDigest =
            $this->derSequence(
                $this->derOid(
                    '1.2.840.113549.1.9.4'
                ),
                $this->derSet(
                    $this->derOctetString(
                        $documentDigest
                    )
                )
            );

        /*
         * ESS signing-certificate-v2.
         *
         * SHA-256 is the default hash algorithm for ESSCertIDv2.
         */
        $essCertIdV2 =
            $this->derSequence(
                $this->derOctetString(
                    hash(
                        'sha256',
                        $certificateDer,
                        true
                    )
                )
            );

        $signingCertificateV2Value =
            $this->derSequence(
                $this->derSequence(
                    $essCertIdV2
                )
            );

        $signingCertificateV2 =
            $this->derSequence(
                $this->derOid(
                    '1.2.840.113549.1.9.16.2.47'
                ),
                $this->derSet(
                    $signingCertificateV2Value
                )
            );

        /*
         * PAdES Baseline:
         *
         * Signing time is stored in the PDF /M field.
         * Do NOT add the CMS signing-time attribute.
         */
        return $this->derSet(
            $contentType,
            $messageDigest,
            $signingCertificateV2
        );
    }

    private function rawEcdsaToDer(
        string $raw
    ): string
    {
        if (
            strlen($raw) % 2 !== 0
        ) {
            throw new InvalidArgumentException(
                'Unexpected raw ECDSA signature length.'
            );
        }

        $half =
            intdiv(
                strlen($raw),
                2
            );

        $r =
            substr(
                $raw,
                0,
                $half
            );

        $s =
            substr(
                $raw,
                $half
            );

        return $this->derSequence(
            $this->derInteger($r),
            $this->derInteger($s)
        );
    }

    private function webEidSignatureForCms(
        string $signatureBase64,
        array  $signatureAlgorithm
    ): string
    {
        $signature =
            base64_decode(
                $signatureBase64,
                true
            );

        if ($signature === false) {
            throw new InvalidArgumentException(
                'Invalid Base64 signature.'
            );
        }

        $crypto =
            strtoupper(
                (string)(
                    $signatureAlgorithm['cryptoAlgorithm'] ?? ''
                )
            );

        /*
         * Web-eID returns ECDSA as IEEE-P1363 r||s.
         *
         * CMS requires ASN.1 DER ECDSA-Sig-Value.
         */
        if (
            $crypto === 'ECC'
            || $crypto === 'EC'
        ) {
            return $this->rawEcdsaToDer(
                $signature
            );
        }

        return $signature;
    }

    private function buildDetachedCms(
        string $certificateDer,
        string $signedAttributesSetDer,
        string $signatureValue,
        array  $signatureAlgorithm
    ): string
    {
        $ids =
            $this->certificateIssuerAndSerial(
                $certificateDer
            );

        $hashFunction =
            (string)(
                $signatureAlgorithm['hashFunction'] ?? ''
            );

        $digestAlgorithm =
            $this->algorithmIdentifier(
                $this->digestOid(
                    $hashFunction
                ),
                true
            );

        $signatureAlgorithmOid =
            $this->signatureOid(
                $signatureAlgorithm
            );

        $crypto =
            strtoupper(
                (string)(
                    $signatureAlgorithm['cryptoAlgorithm'] ?? ''
                )
            );

        /*
         * ECDSA parameters MUST be absent.
         * RSA hash-with-RSA may contain NULL.
         */
        $signatureAlgorithmDer =
            $this->algorithmIdentifier(
                $signatureAlgorithmOid,
                $crypto === 'RSA'
            );

        /*
         * SignerInfo signedAttrs is:
         *
         * [0] IMPLICIT SET OF Attribute
         *
         * Replace SET tag 0x31 with context tag 0xA0.
         */
        if (
            $signedAttributesSetDer === ''
            || ord(
                $signedAttributesSetDer[0]
            ) !== 0x31
        ) {
            throw new RuntimeException(
                'Signed attributes are not a DER SET.'
            );
        }

        $signedAttributesImplicit =
            chr(0xA0)
            . substr(
                $signedAttributesSetDer,
                1
            );

        $signerIdentifier =
            $this->derSequence(
                $ids['issuer_raw'],
                $this->derInteger(
                    $ids['serial_raw']
                )
            );

        $signerInfo =
            $this->derSequence(
                $this->derInteger(1),
                $signerIdentifier,
                $digestAlgorithm,
                $signedAttributesImplicit,
                $signatureAlgorithmDer,
                $this->derOctetString(
                    $signatureValue
                )
            );

        $signedData =
            $this->derSequence(
                $this->derInteger(1),

                $this->derSet(
                    $digestAlgorithm
                ),

                /*
                 * Detached id-data.
                 */
                $this->derSequence(
                    $this->derOid(
                        '1.2.840.113549.1.7.1'
                    )
                ),

                /*
                 * certificates [0] IMPLICIT CertificateSet
                 */
                $this->der(
                    0xA0,
                    $certificateDer
                ),

                $this->derSet(
                    $signerInfo
                )
            );

        /*
         * ContentInfo signedData.
         */
        return $this->derSequence(
            $this->derOid(
                '1.2.840.113549.1.7.2'
            ),
            $this->der(
                0xA0,
                $signedData
            )
        );
    }

    /**
     * ---------------------------------------------------------------------
     * Verification
     * ---------------------------------------------------------------------
     */

    private function verifyWebEidSignatureOverSignedAttributes(
        string $signedAttributesSetDer,
        string $certificateBase64,
        string $signatureBase64,
        array  $signatureAlgorithm
    ): bool
    {
        $signature =
            $this->webEidSignatureForCms(
                $signatureBase64,
                $signatureAlgorithm
            );

        $hashFunction =
            (string)(
                $signatureAlgorithm['hashFunction'] ?? ''
            );

        $pem =
            $this->base64DerCertificateToPem(
                $certificateBase64
            );

        $publicKey =
            openssl_pkey_get_public(
                $pem
            );

        if ($publicKey === false) {
            throw new RuntimeException(
                'Could not extract certificate public key.'
            );
        }

        $result =
            openssl_verify(
                $signedAttributesSetDer,
                $signature,
                $publicKey,
                $this->hashNameForPhp(
                    $hashFunction
                )
            );

        return $result === 1;
    }

    /**
     * Optional additional CMS verification.
     *
     * Returns null when the OpenSSL executable cannot be used.
     */
    private function verifyFinalPdfCmsWithOpenSsl(
        string $pdf,
        array  $byteRange,
        string $cmsDer
    ): ?bool
    {
        if (
            !function_exists('exec')
        ) {
            return null;
        }

        $openssl =
            trim(
                (string)@shell_exec(
                    'command -v openssl 2>/dev/null'
                )
            );

        if ($openssl === '') {
            return null;
        }

        $directory =
            sys_get_temp_dir()
            . '/eid-pades-'
            . bin2hex(
                random_bytes(8)
            );

        if (
            !mkdir(
                $directory,
                0700,
                true
            )
            && !is_dir($directory)
        ) {
            return null;
        }

        $cmsFile =
            $directory
            . '/signature.der';

        $dataFile =
            $directory
            . '/signed-data.bin';

        $outputFile =
            $directory
            . '/verified.out';

        try {
            file_put_contents(
                $cmsFile,
                $cmsDer
            );

            file_put_contents(
                $dataFile,
                $this->getPdfByteRangeBytes(
                    $pdf,
                    $byteRange
                )
            );

            $command =
                escapeshellarg($openssl)
                . ' cms -verify'
                . ' -binary'
                . ' -inform DER'
                . ' -noverify'
                . ' -in '
                . escapeshellarg($cmsFile)
                . ' -content '
                . escapeshellarg($dataFile)
                . ' -out '
                . escapeshellarg($outputFile)
                . ' 2>&1';

            exec(
                $command,
                $output,
                $exitCode
            );

            return $exitCode === 0;
        } finally {
            @unlink($cmsFile);
            @unlink($dataFile);
            @unlink($outputFile);
            @rmdir($directory);
        }
    }
}