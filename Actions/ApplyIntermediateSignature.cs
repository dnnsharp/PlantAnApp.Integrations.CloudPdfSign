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
using System.Xml.Linq;
using System.Linq;
using System.Security.Cryptography;

namespace PlantAnApp.Integrations.CloudPdfSign.Actions {
    public class ApplyIntermediateSignature : IActionImpl {

        [ActionParameter(ApplyTokens = true)]
        public bool UserNeedsEnrolment { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string ExternalId { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string FileIdentifier { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string TncFileIdentifier { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Folder { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SignReason { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SignLocation { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SignerName { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public int SignatureFontSize { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public int SignaturePageNumber { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string SignatureFieldName { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public int LowerLeftX { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public int LowerLeftY { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public int UpperRightX { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public int UpperRightY { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string DocumentTitle { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string BlankSignedFileIdOutputToken { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string SessionId { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string SignatureFieldNameOutputToken { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public ActionEvent OnError { get; set; }

        public void Init(StringsDictionary actionTypeSettings, SettingsDictionary actionSettings) {
        }

        public IActionResult Execute(ActionContext context) {
            byte[] tnc = null;
            var folder = StorageUtils.GetOrCreateFolder(context.PortalSettings.PortalId, Folder);


            if (UserNeedsEnrolment) {
                var tncFile = StorageUtils.GetFile(TncFileIdentifier, context);
                if (tncFile is null) {
                    throw new InternalException("No TNC file provided.");
                }
                using (var fileStream = FileManager.Instance.GetFileContent(tncFile))
                    tnc = SHA1.Create().ComputeHash(fileStream);
            }

            if (string.IsNullOrEmpty(BlankSignedFileIdOutputToken))
                throw new InternalException("No output token set for the blank signature document file.");

            if (string.IsNullOrEmpty(SessionId))
                throw new InternalException("No output token set for the session ID.");

            var pdfSigRectangle = new PDFSignatureRectangle(100, 100, 200, 200);
            if (LowerLeftX > -1 && LowerLeftY > -1 && UpperRightX > -1 && UpperRightY > -1)
                pdfSigRectangle = new PDFSignatureRectangle(LowerLeftX, LowerLeftY, UpperRightX, UpperRightY);
            try {
                using (new Tls12Context(System.Net.SecurityProtocolType.Tls12)) {
                    var blankSignedPdfs = new List<IntermediateSignature>();
                    var signingServiceClient = CreateServiceClient<SigningServiceContractChannel>("BasicHttpBinding_SigningServiceContract");

                    var signProv = SignatureProviderFactory.GetSignatureProvider();
                    var pdfSignatureOptions = new PDFVisibilityOptions {
                        SignatureRectangle = pdfSigRectangle,
                        FontSize = 10,
                    };
                    if (!string.IsNullOrEmpty(SignatureFieldName))
                        pdfSignatureOptions.SignatureFieldName = SignatureFieldName;

                    if (SignaturePageNumber != -1)
                        pdfSignatureOptions.SignaturePageNumber = SignaturePageNumber;

                    if (SignatureFontSize != -1)
                        pdfSignatureOptions.FontSize = SignatureFontSize;

                    var scs = new PDFSigningContextSettings {
                        Reason = SignReason,
                        Location = SignLocation,
                        SignatureType = SignatureTypeEnum.CUSTOM_SIGNATURE,
                        VisibilityOptions = pdfSignatureOptions
                    };
                    DocumentInfo.DocumentDataType documentDataType = DocumentInfo.DocumentDataType.DocumentHashPAdES;

                    foreach (var file in FileIdentifier.Split(';')) {
                        var fileInfo = StorageUtils.GetFile(file, context);
                        if (fileInfo is null) {
                            throw new InternalException("No PDF file provided.");
                        }

                        using (var cont = FileManager.Instance.GetFileContent(fileInfo)) {
                            var ms = new MemoryStream();
                            cont.CopyTo(ms);
                            var pdfBytes = ms.ToArray();

                            var intermediateSig = signProv.GetIntermediateSignature(pdfBytes, SignerName, scs, documentDataType);
                            blankSignedPdfs.Add(intermediateSig);
                        }
                    }

                    var sr = new SigningRequest {
                        ExternalId = ExternalId,

                    };
                    var docTitles = DocumentTitle.Split(',').ToArray();
                    int index = 0;
                    var documentInfos = new List<DocumentInfo>();
                    foreach (var blankSignedPdf in blankSignedPdfs) {
                        var docInfo = new DocumentInfo() {
                            Hash = blankSignedPdf.Hash,
                            DataType = documentDataType,
                            Title = docTitles[index],
                        };
                        documentInfos.Add(docInfo);
                        index++;
                    }
                    sr.MasterHash = SHA256.Create().ComputeHash(blankSignedPdfs.SelectMany(dcoInfo => dcoInfo.Hash).ToArray());
                    //sr.MasterHash = blankSignedPdfs.SelectMany(dcoInfo => dcoInfo.Hash).ToArray();
                    sr.Documents = documentInfos.ToArray();
                    var listOfFileIds = new List<string>();
                    // Initiate signing for obtain the value for dession id.
                    string sessionId = signingServiceClient.InitiateSigning(sr, tnc);
                    index = 0;
                    foreach (var blankSignedPdf in blankSignedPdfs) {
                        var addedFile = FileManager.Instance.AddFile(folder, sessionId + index + "-blank.pdf", new MemoryStream(blankSignedPdf.BlankSignature), true);
                        listOfFileIds.Add(addedFile.FileId.ToString());
                        context[SignatureFieldNameOutputToken] = blankSignedPdf.SignatureFieldName;
                        index++;
                    }

                    context[BlankSignedFileIdOutputToken] = string.Join(";", listOfFileIds);
                    context[SessionId] = sessionId;

                }
            } catch (Exception ex) {
                context.CurrentException = ex;
                if (ex is System.ServiceModel.FaultException fault) {
                    var errorXml = XElement.Parse(fault.CreateMessageFault().GetReaderAtDetailContents().ReadOuterXml());
                    var errorMessage = errorXml.Elements().ToDictionary(key => key.Name.LocalName, val => val.Value)["Message"];
                    context["Presign:Error"] = errorMessage;
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
    }
}
