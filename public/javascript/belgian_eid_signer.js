import {
    status,
    getSigningCertificate,
    sign
} from './web-eid.js';

document.addEventListener('DOMContentLoaded', () => {

    const btnSign = document.getElementById(
        SIGNING.buttonId ?? 'btnSign'
    );

    if (!btnSign) {
        console.error('Belgian eID signing button not found.');
        return;
    }

    btnSign.addEventListener('click', async () => {

        btnSign.disabled = true;

        try {
            console.log('Checking Web-eID status...');

            const webEidStatus = await status();
            console.log('Web-eID status:', webEidStatus);

            console.log('Fetching signing certificate...');

            const certificateResult = await getSigningCertificate();

            console.log(
                'Certificate result:',
                certificateResult
            );

            console.log('Preparing PDF...');

            const response = await fetch(
                '/belgian-eid/signing/prepare',
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        jobId: SIGNING.jobId,
                        certificate: certificateResult.certificate,
                        supportedSignatureAlgorithms:
                        certificateResult.supportedSignatureAlgorithms
                    })
                }
            );

            const result = await response.json();

            console.log('Prepare response:', result);

            if (!response.ok || !result.success) {
                throw new Error(
                    result.error ?? 'PDF could not be prepared.'
                );
            }

            console.log('PDF successfully prepared!');
            console.log('Hash:', result.hash);
            console.log('Hash function:', result.hashFunction);

            console.log('Signing document with eID...');

            const signatureResult = await sign(
                certificateResult.certificate,
                result.hash,
                result.hashFunction
            );

            console.log('Signature result:', signatureResult);
            console.log('Document successfully signed by Web-eID!');

            console.log('Processing signature in PDF...');

            const finalizeResponse = await fetch(
                '/belgian-eid/signing/finalize',
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        jobId: SIGNING.jobId,
                        signature: signatureResult.signature,
                        signatureAlgorithm: signatureResult.signatureAlgorithm
                    })
                }
            );

            const finalizeResult = await finalizeResponse.json();

            console.log('Finalize response:', finalizeResult);

            if (!finalizeResponse.ok || !finalizeResult.success) {
                throw new Error(
                    finalizeResult.error ??
                    'The digital signature could not be processed in the PDF.'
                );
            }

            console.log('PDF successfully signed!');
            console.log('Signed PDF:', finalizeResult.filename);

            if (!finalizeResult.returnUrl) {
                throw new Error(
                    'No return URL received after signing.'
                );
            }

            window.location.href = finalizeResult.returnUrl;

        } catch (error) {

            console.error('Signing error:', error);
            console.error('Name:', error?.name);
            console.error('Code:', error?.code);
            console.error('Message:', error?.message);

            alert(
                error?.message ??
                'The document could not be prepared.'
            );

        } finally {
            btnSign.disabled = false;
        }
    });
});