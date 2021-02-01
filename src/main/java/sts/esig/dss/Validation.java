package sts.esig.dss;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import javax.swing.JFileChooser;
import javax.xml.transform.Result;
import javax.xml.transform.sax.SAXResult;

import org.apache.commons.io.FilenameUtils;
import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FopFactoryBuilder;
import org.apache.fop.apps.MimeConstants;

import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class Validation{

	private TrustedListsCertificateSource tslCertificateSource;
	private FileCacheDataLoader onlineOfflineFileLoader;
	private CommonsDataLoader commonsHttpDataLoader;
	private CacheCleaner cacheCleaner;
	private LOTLSource lotlSource;
	private String location;
	private OutputStream osSimple;
	private OutputStream osDetailed;
	private File simpleReport = null;
	private File detailedReport = null;
	
	public void setOnlineEUTLList(String ks, String pswd, String EUTL) throws IOException
	{
		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File(ks), "PKCS12", pswd);

		lotlSource = new LOTLSource();
		lotlSource.setUrl(EUTL);
		lotlSource.setCertificateSource(keyStoreCertificateSource);
		lotlSource.setPivotSupport(true);
	}

	public void setOfflineEUTLList(String ks, String pswd, String EUTL) throws IOException
	{
		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File(ks), "PKCS12", pswd);

		lotlSource = new LOTLSource();
		//lotlSource.setUrl("E:\\eutl.xml");
		lotlSource.setUrl(EUTL);
		lotlSource.setCertificateSource(keyStoreCertificateSource);
		lotlSource.setPivotSupport(true);
	}

	public void setOnlineLoader()
	{
		commonsHttpDataLoader = new CommonsDataLoader();
		onlineOfflineFileLoader = new FileCacheDataLoader(commonsHttpDataLoader);
		tslCertificateSource = new TrustedListsCertificateSource();

		cacheCleaner = new CacheCleaner();
		cacheCleaner.setCleanFileSystem(true);
		cacheCleaner.setDSSFileLoader(onlineOfflineFileLoader);
	}

	public void setOfflineLoader()
	{
		onlineOfflineFileLoader = new FileCacheDataLoader();
		onlineOfflineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		onlineOfflineFileLoader.setDataLoader(new IgnoreDataLoader());

		cacheCleaner = new CacheCleaner();
		cacheCleaner.setCleanMemory(true);
		cacheCleaner.setCleanFileSystem(true);
		cacheCleaner.setDSSFileLoader(onlineOfflineFileLoader);
	}

	public TLAlert tlSigningAlert() {
		TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
		LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
		return new TLAlert(signingDetection, handler);
	}

	public TLAlert tlExpirationDetection() {
		TLExpirationDetection expirationDetection = new TLExpirationDetection();
		LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
		return new TLAlert(expirationDetection, handler);
	}

	public LOTLAlert ojUrlAlert(LOTLSource source) {
		OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(source);
		LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
		return new LOTLAlert(ojUrlDetection, handler);
	}

	public void saveFile() 
	{
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		fileChooser.setDialogTitle("Specify a location to save ETSI Validation Reports");

		fileChooser.showSaveDialog(null);

		this.location = fileChooser.getSelectedFile().getAbsolutePath();
		//return fileChooser.getSelectedFile().getAbsolutePath();
	}

	public void Validate(String doc, String ks, String pswd, String EUTL) throws Exception
	{
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(new CommonsDataLoader());
		cv.setOcspSource(new OnlineOCSPSource());
		cv.setCrlSource(new OnlineCRLSource());

		//setOfflineLoader();
		//setOfflineEUTLList();

		setOnlineLoader();
		setOnlineEUTLList(ks, pswd, EUTL);

		TLValidationJob validationJob = new TLValidationJob();
		validationJob.setTrustedListCertificateSource(tslCertificateSource);
		//validationJob.setOfflineDataLoader(onlineOfflineFileLoader);
		validationJob.setOnlineDataLoader(onlineOfflineFileLoader);
		validationJob.setCacheCleaner(cacheCleaner);
		validationJob.setListOfTrustedListSources(lotlSource);
		validationJob.onlineRefresh();
		//validationJob.offlineRefresh();
		//validationJob.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));

		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		//commonCertificateVerifier.setTrustedCertSources(tslCertificateSource);

		cv.setTrustedCertSources(tslCertificateSource);

		DSSDocument document = new FileDocument(new File(doc));

		SignedDocumentValidator documentValidator = PDFDocumentValidator.fromDocument(document);
		documentValidator.setCertificateVerifier(cv);

		Reports reports = documentValidator.validateDocument();

		//List<String> errors = reports.getSimpleReport().getSignatureIdList();

		//for(int i=0;i<errors.size();i++)
		//{
		//	System.out.print(reports.getSimpleReport().getErrors(errors.get(i)));
		//}

		FopFactoryBuilder builder = new FopFactoryBuilder(new File(".").toURI());
		builder.setAccessibility(true);

		FopFactory fopFactory = builder.build();

		FOUserAgent foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setAuthor("STS-PKI ETSI Validation");
		foUserAgent.setAccessibility(true);

		String nameFile = FilenameUtils.removeExtension(doc.substring(doc.lastIndexOf("\\")+1));
		
		// raport detaliat
		this.osDetailed = new FileOutputStream(location+"//ETSIDetailedReport-"+nameFile+".pdf");

		Fop fopDetailed = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, osDetailed);

		Result resultDetailed = new SAXResult(fopDetailed.getDefaultHandler());

		DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
		detailedReportFacade.generatePdfReport(reports.getXmlDetailedReport(), resultDetailed);
		osDetailed.close();

		// raport simplu
		this.osSimple = new FileOutputStream(location+"//ETSISimpleReport-"+nameFile+".pdf");

		Fop fopSimple = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, osSimple);

		Result resultSimple = new SAXResult(fopSimple.getDefaultHandler());

		SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();
		simpleReportFacade.generatePdfReport(reports.getXmlSimpleReport(), resultSimple);
		osSimple.close();

		//System.exit(0);
	}

	static public void main(String[] args) throws Exception
	{		
		Validation val = new Validation();
		val.saveFile();
		val.Validate("E:\\Newfolder\\sample-signed.pdf", "C:\\Users\\bogdan\\Downloads\\keystore.p12",
				"dss-password", "https://ec.europa.eu/tools/lotl/eu-lotl.xml");
	}

	public File getOsSimple() {
		return this.simpleReport;
	}

	public File getOsDetailed() {
		return this.detailedReport;
	}
}