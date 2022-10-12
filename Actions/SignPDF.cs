using DnnSharp.Common;
using DnnSharp.Common.Actions;
using System;
using Paperless.DotNetSdk.EnrollmentServiceRef;
using Paperless.DotNetSdk.SigningServiceRef;
using Paperless.DotNetSdk.SignatureProvider;
using Paperless.DotNetSdk;
using Paperless.DotNetSdk.EnrollmentData;
using System.Runtime.Serialization;
using DotNetNuke.Services.FileSystem;
using System.IO;
using System.Configuration;
using System.ServiceModel.Configuration;
using DnnSharp.Common.Security;
using System.Collections.Generic;
using DnnSharp.Common.IO;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto.Tls;
using System.Xml;
using System.Xml.Linq;
using System.Linq;

namespace PlantAnApp.Integrations.CloudPdfSign.Actions {
    public class SignPDF : IActionImpl {

        [ActionParameter(ApplyTokens = true)]
        public bool UserNeedsEnrolment { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string ExternalId { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SessionId { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SmsCode { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SignatureFieldName { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string DocumentTitle { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string FileIdentifier { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Folder { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string OutputTokenName { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string SignedTncOutputToken { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public ActionEvent OnError { get; set; }

        public void Init(StringsDictionary actionTypeSettings, SettingsDictionary actionSettings) {
        }

        public IActionResult Execute(ActionContext context) {

            if (string.IsNullOrEmpty(SessionId))
                throw new InternalException("No session ID was provided.");

            if (string.IsNullOrEmpty(SmsCode))
                throw new InternalException("No sms code was provided.");

            if (string.IsNullOrEmpty(SignatureFieldName))
                throw new InternalException("No signature field name was provided.");


            var folder = StorageUtils.GetOrCreateFolder(context.PortalSettings.PortalId, Folder);
            try {
                using (new Tls12Context(System.Net.SecurityProtocolType.Tls12)) {
                    byte[] tnc = null;

                    AuthorizationRequest oAuthorizationRequest = new AuthorizationRequest {
                        // Set some properties to above object.
                        SessionId = SessionId,
                        Code = SmsCode // The value of code received by SMS.
                    };

                    var signingServiceClient = CreateServiceClient<SigningServiceContractChannel>("BasicHttpBinding_SigningServiceContract") as SigningServiceContract;

                    // Authorize signing is called for obtain the signing response.
                    SigningResponse oSigningResponse = signingServiceClient.AuthorizeSigning(oAuthorizationRequest);
                    if (UserNeedsEnrolment)
                        tnc = signingServiceClient.GetSignedTermsAndConditions(ExternalId);

                    // Close the signing service client object.
                    ((SigningServiceContractChannel)signingServiceClient).Close();



                    var signProv = SignatureProviderFactory.GetSignatureProvider();
                    var listOfFileIds = new List<string>();
                    int index = 0;
                    var docTitles = DocumentTitle.Split(',').ToArray();
                    foreach (var file in FileIdentifier.Split(';')) {
                        byte[] sigBytes = oSigningResponse.Signatures.Where(sig => string.Equals(sig.Title, docTitles[index])).FirstOrDefault().Signature;
                        var fileInfo = StorageUtils.GetFile(file, context);
                        if (fileInfo is null) {
                            throw new InternalException("No blank signature file provided.");
                        }
                        using (var cont = FileManager.Instance.GetFileContent(fileInfo)) {
                            var ms = new MemoryStream();
                            cont.CopyTo(ms);
                            var pdfBytes = ms.ToArray();
                            byte[] sigPdf = signProv.EmbedSignature(pdfBytes, sigBytes, SignatureFieldName);
                            AdobeLtvEnable(ref sigPdf, SignatureFieldName);
                            var stream = new MemoryStream(sigPdf);
                            var signedPdf = FileManager.Instance.AddFile(folder, SessionId + index + "-signed.pdf", stream);
                            listOfFileIds.Add(signedPdf.FileId.ToString());
                        }
                        index++;
                    }

                    context[OutputTokenName] = string.Join(";", listOfFileIds);

                    if (!(tnc is null)) {
                        var signedTnc = FileManager.Instance.AddFile(folder, "tnc-signed.pdf", new MemoryStream(tnc));
                        context[SignedTncOutputToken] = signedTnc.FileId;
                    }
                }

            } catch (Exception ex) {
                context.CurrentException = ex;
                if (ex is System.ServiceModel.FaultException fault) {
                    var errorXml = XElement.Parse(fault.CreateMessageFault().GetReaderAtDetailContents().ReadOuterXml());
                    var errorMessage = errorXml.Elements().ToDictionary(key => key.Name.LocalName, val => val.Value)["Message"];
                    context["Sign:Error"] = errorMessage;
                    context.Log(DnnSharp.Common.Logging.eLogLevel.Error, errorMessage);
                }
                if (OnError.HasActions)
                    return OnError.Execute(context);
                else
                    throw;
            }
            return null;
        }
        public T CreateServiceClient<T>(string configBindingName) {
            Configuration configuration = ConfigurationManager.OpenExeConfiguration(new Uri(typeof(ServiceManager).Assembly.GetName().CodeBase).LocalPath);
            return new ConfigurationChannelFactory<T>(configBindingName, configuration, null).CreateChannel();
        }

        public void AdobeLtvEnable(ref byte[] arrSignedBytes, string signatureFieldName, bool bWithCrl = true) {
            using (MemoryStream memoryStream = new MemoryStream()) {
                var pdfReader = new PdfReader(arrSignedBytes);
                var pdfStamper = new PdfStamper(pdfReader, memoryStream, '\0', append: true);
                pdfStamper.Writer.CloseStream = false;

                var adobeLtvEnabling = new AdobeLtvEnabling(pdfStamper, DigestAlgorithm.SHA1, true, bWithCrl);
                var ocspClient = new OcspClientBouncyCastle(new OcspVerifier(null, null));

                var crlClient = new CrlClientOnline();

                adobeLtvEnabling.enable(ocspClient, crlClient, signatureFieldName);

                var subjectFields = iTextSharp.text.pdf.security.CertificateInfo.GetSubjectFields(pdfStamper.AcroFields.VerifySignature(signatureFieldName).SigningCertificate);
                var field = subjectFields.GetField("CN");

                if (string.IsNullOrEmpty(field)) {
                    field = subjectFields.GetField("E");
                }

                pdfStamper.Close();
                pdfReader.Close();
                arrSignedBytes = memoryStream.ToArray();
            }
        }

    }

}
