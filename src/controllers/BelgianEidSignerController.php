<?php

namespace Controller;

use JsonException;
use RuntimeException;
use Throwable;
use Tigress\BelgianEidSigner;

/**
 * Class BelgianEidSignerController (PHP version 8.5)
 *
 * @author Rudy Mas <rudy.mas@rudymas.be>
 * @copyright 2026 GO! Next (https://www.go-next.be)
 * @license Proprietary
 * @version 2026.09.25.0
 * @package Controller
 */
class BelgianEidSignerController
{
    /**
     * @return void
     * @throws JsonException
     */
    public function prepareSigning(): void
    {
        header('Content-Type: application/json; charset=utf-8');

        try {
            $input = json_decode(
                file_get_contents('php://input'),
                true,
                512,
                JSON_THROW_ON_ERROR
            );

            $jobId = $input['jobId'] ?? '';
            $certificate = $input['certificate'] ?? '';
            $supportedAlgorithms = $input['supportedSignatureAlgorithms'] ?? [];

            if (
                $jobId === '' ||
                $certificate === '' ||
                !isset($_SESSION['eid_signing'][$jobId])
            ) {
                throw new RuntimeException('Ongeldige signing job.');
            }

            $job = $_SESSION['eid_signing'][$jobId];

            if ((time() - $job['createdAt']) > 300) {
                unset($_SESSION['eid_signing'][$jobId]);
                throw new RuntimeException('De signing job is verlopen.');
            }

            if (!is_file($job['sourceFile'])) {
                throw new RuntimeException('Het PDF-bestand bestaat niet.');
            }

            $preparedFile = dirname($job['sourceFile'])
                . '/prepared_' . $jobId . '.pdf';

            $signer = new BelgianEidSigner();

            $result = $signer->prepare(
                sourceFile: $job['sourceFile'],
                preparedFile: $preparedFile,
                certificate: $certificate,
                supportedAlgorithms: $supportedAlgorithms,
                fieldName: $job['fieldName'],
                position: $job['position']
            );

            /*
             * VOOR DEZE TEST:
             * bewaar gewoon het volledige prepare-resultaat.
             */
            $_SESSION['eid_signing'][$jobId]['preparedFile'] = $preparedFile;
            $_SESSION['eid_signing'][$jobId]['prepareResult'] = $result;
            $_SESSION['eid_signing'][$jobId]['certificate'] = $certificate;

            echo json_encode([
                'success' => true,
                'jobId' => $jobId,
                'hash' => $result['hash'],
                'hashFunction' => $result['hashFunction'],
            ], JSON_THROW_ON_ERROR);

        } catch (Throwable $e) {
            http_response_code(400);

            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
            ], JSON_THROW_ON_ERROR);
        }

        exit;
    }

    /**
     * @return void
     * @throws JsonException
     */
    public function finalizeSigning(): void
    {
        header('Content-Type: application/json; charset=utf-8');

        try {
            $input = json_decode(
                file_get_contents('php://input'),
                true,
                512,
                JSON_THROW_ON_ERROR
            );

            $jobId = $input['jobId'] ?? '';
            $signature = $input['signature'] ?? '';
            $signatureAlgorithm = $input['signatureAlgorithm'] ?? [];

            if (
                $jobId === '' ||
                $signature === '' ||
                !isset($_SESSION['eid_signing'][$jobId])
            ) {
                throw new RuntimeException('Ongeldige signing job.');
            }

            $job = $_SESSION['eid_signing'][$jobId];

            if ((time() - $job['createdAt']) > 300) {
                unset($_SESSION['eid_signing'][$jobId]);

                throw new RuntimeException(
                    'De signing job is verlopen.'
                );
            }

            if (
                empty($job['preparedFile']) ||
                !is_file($job['preparedFile']) ||
                empty($job['prepareResult']) ||
                empty($job['certificate'])
            ) {
                throw new RuntimeException(
                    'De signing job is niet correct voorbereid.'
                );
            }

            $finalFile = dirname($job['sourceFile'])
                . '/signed_' . $jobId . '.pdf';

            $signer = new BelgianEidSigner();

            /*
             * De waarden hieronder komen uit het resultaat
             * van prepare(), dat we server-side hebben bewaard.
             */
            $prepareResult = $job['prepareResult'];

            $signer->finalize(
                preparedFile: $job['preparedFile'],
                outputFile: $finalFile,
                certificate: $job['certificate'],
                signatureBase64: $signature,
                signatureAlgorithm: $signatureAlgorithm,
                byteRange: $prepareResult['byteRange'],
                contentsPos: $prepareResult['contentsPos'],
                contentsHexLength: $prepareResult['contentsHexLength'],
                signedAttributesBase64: $prepareResult['signedAttributes']
            );

            $_SESSION['eid_signing'][$jobId]['finalFile'] = $finalFile;

            echo json_encode([
                'success' => true,
                'jobId' => $jobId,
                'filename' => basename($finalFile),
                'returnUrl' => $job['returnUrl'],
            ], JSON_THROW_ON_ERROR);

        } catch (Throwable $e) {
            http_response_code(400);

            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
            ], JSON_THROW_ON_ERROR);
        }

        exit;
    }
}