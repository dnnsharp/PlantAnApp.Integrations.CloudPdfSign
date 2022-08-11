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

namespace PlantAnApp.Integrations.PdfAutoSigner.Actions {
    public class EnrolUser : IActionImpl {

        [ActionParameter(ApplyTokens = true)]
        public string ExternalId { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string FirstName { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string LastName { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string CNP { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string CountryCode { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Email { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string PhoneNumber { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string CustomPhotoFileId { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Locality { get; set; }
        [ActionParameter(ApplyTokens = true)]
        public string District { get; set; }
        [ActionParameter(ApplyTokens = true)]
        public string Address { get; set; }
        [ActionParameter(ApplyTokens = true)]
        public string Sector { get; set; }
        [ActionParameter(ApplyTokens = true)]
        public string Street { get; set; }
        [ActionParameter(ApplyTokens = true)]
        public string StreetNumber { get; set; }
        [ActionParameter(ApplyTokens = true)]
        public string ZIPCode { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Apartment { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Block { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Entrance { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string IdCardExpirationDate { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string IdCardIssueDate { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string IdCardIssuer { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string IdCardNumber { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string IdCardSerial { get; set; }

        [ActionParameter(ApplyTokens = true)]
        public string Folder { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string OutputTokenName { get; set; }

        [ActionParameter(IsOutputToken = true)]
        public string FileIdOutputTokenName { get; set; }


        public void Init(StringsDictionary actionTypeSettings, SettingsDictionary actionSettings) {
        }

        public IActionResult Execute(ActionContext context) {
            var needsEnrolment = false;
            var folder = StorageUtils.GetOrCreateFolder(context.PortalSettings.PortalId, Folder);

            try {
                using (var enrollmentServiceClient = CreateServiceClient<EnrollmentServiceContractChannel>("BasicHttpBinding_EnrollmentServiceContract")) {
                    var certInfo = enrollmentServiceClient.GetCertificate(ExternalId);
                    if (certInfo is null)
                        needsEnrolment = true;
                }
            } catch (Exception ex) {
                needsEnrolment = true;
            }
            context[OutputTokenName] = needsEnrolment;

            if (needsEnrolment == false)
                return null;

            var file = StorageUtils.GetFile(CustomPhotoFileId, context);
            if (file is null) {
                throw new InternalException("No ID card photo provided.");
            }

            var cont = FileManager.Instance.GetFileContent(file);
            var ms = new MemoryStream();
            cont.CopyTo(ms);
            var bytes = ms.ToArray();

            try {

                using (new Tls12Context(System.Net.SecurityProtocolType.Tls12)) {
                    var enrolRequest = new EnrolmentRequest {
                        ExternalId = ExternalId,  //req
                        FirstName = FirstName, //req
                        LastName = LastName, //req
                        Cnp = CNP, //req
                        Country = CountryCode, //req
                        Email = Email, //req
                        PhoneNumber = PhoneNumber, //req
                        CustomerIdPhoto = bytes, // req
                        Address = Address, //req
                    };

                    AppendRequestDetails(enrolRequest);

                    using (var enrollmentServiceClient = CreateServiceClient<EnrollmentServiceContractChannel>("BasicHttpBinding_EnrollmentServiceContract")) {
                        //what does this return
                        enrollmentServiceClient.EnrollUser(enrolRequest);
                    }

                    using (var signingServiceClient = CreateServiceClient<SigningServiceContractChannel>("BasicHttpBinding_SigningServiceContract")) {
                        var tnc = signingServiceClient.GetGeneralTermsAndConditions(ExternalId);
                        var tncFile = FileManager.Instance.AddFile(folder, "TermsAndConditions.pdf", new MemoryStream(tnc.FileTermsAndConditions), true);
                        if (!string.IsNullOrEmpty(FileIdOutputTokenName))
                            context[FileIdOutputTokenName] = tncFile.FileId;
                    }
                }
            } catch (Exception ex) {
                context.CurrentException = ex;
                if (ex is System.ServiceModel.FaultException fault) {
                    var errorXml = XElement.Parse(fault.CreateMessageFault().GetReaderAtDetailContents().ReadOuterXml());
                    var errorMessage = errorXml.Elements().ToDictionary(key => key.Name.LocalName, val => val.Value)["Message"];
                    context["EnrolUser"] = errorMessage;
                    context.Log(DnnSharp.Common.Logging.eLogLevel.Error, errorMessage);
                }
            }

            return null;
        }

        private void AppendRequestDetails(EnrolmentRequest enrolRequest) {
            if (!string.IsNullOrEmpty(Locality))
                enrolRequest.Locality = Locality;

            if (!string.IsNullOrEmpty(District))
                enrolRequest.District = District;

            if (!string.IsNullOrEmpty(Sector))
                enrolRequest.Sector = Sector;

            if (!string.IsNullOrEmpty(Street))
                enrolRequest.Street = Street;

            if (!string.IsNullOrEmpty(StreetNumber))
                enrolRequest.Street = StreetNumber;

            if (!string.IsNullOrEmpty(ZIPCode))
                enrolRequest.ZIPCode = ZIPCode;

            if (!string.IsNullOrEmpty(Apartment))
                enrolRequest.Apartment = Apartment;

            if (!string.IsNullOrEmpty(Block))
                enrolRequest.Block = Block;

            if (!string.IsNullOrEmpty(Entrance))
                enrolRequest.Entrance = Entrance;

            if (DateTime.TryParse(IdCardExpirationDate, out var IdExpiration))
                enrolRequest.IdCardExpirationDate = IdExpiration;

            if (DateTime.TryParse(IdCardIssueDate, out var IdIssue))
                enrolRequest.IdCardIssueDate = IdIssue;

            if (!string.IsNullOrEmpty(IdCardIssuer))
                enrolRequest.IdCardIssuer = IdCardIssuer;

            if (!string.IsNullOrEmpty(IdCardNumber))
                enrolRequest.IdCardNumber = IdCardNumber;

            if (!string.IsNullOrEmpty(IdCardSerial))
                enrolRequest.IdCardSerial = IdCardSerial;
        }

        public T CreateServiceClient<T>(string configBindingName) {
            Configuration configuration = ConfigurationManager.OpenExeConfiguration(new Uri(typeof(ServiceManager).Assembly.GetName().CodeBase).LocalPath);
            return new ConfigurationChannelFactory<T>(configBindingName, configuration, null).CreateChannel();
        }
    }
}
