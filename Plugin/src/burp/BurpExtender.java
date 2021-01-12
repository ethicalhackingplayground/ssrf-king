package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;


public class BurpExtender implements IBurpExtender, IExtensionStateListener, IScannerCheck {
    private IBurpCollaboratorClientContext context;
    private PrintWriter stdout;
    public IBurpExtenderCallbacks callback;
	public IExtensionHelpers helpers;
	public String payload;
	public String payloadWithoutHttp;
	private HashSet<String> client_ips;

	
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	stdout = new PrintWriter(callbacks.getStdout(), true);
    	this.callback=callbacks;
    	helpers=callbacks.getHelpers();
        callbacks.setExtensionName("SSRF-King 1.1");

        stdout.println("Contributor:\n\tBlake (zoid) (twitter.com/z0idsec)\n\t");
        stdout.println("Installation complete.");
        context=callbacks.createBurpCollaboratorClientContext();
        
        payloadWithoutHttp=context.generatePayload(true);
        payload="http://"+payloadWithoutHttp;

        callbacks.registerExtensionStateListener(this);
        callbacks.registerScannerCheck(this);
        
        stdout.println("Payload: " + payload + "\n");
        
        client_ips=GetUserIP();
    }
    
    

	@Override
	public void extensionUnloaded() {
		// TODO Auto-generated method stub
		stdout.println("Finished..");
	}
    

	@Override
	public int consolidateDuplicateIssues(IScanIssue arg0, IScanIssue arg1) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse arg0, IScannerInsertionPoint arg1) {
		// TODO Auto-generated method stub
		List<IScanIssue> issues = new ArrayList<IScanIssue>();
		return issues;
	}
	
	
	public HashSet<String> GetUserIP() {
		HashSet<String> client_ips = new HashSet<>();

	        try {
	            String pollPayload = context.generatePayload(true);
	            callback.makeHttpRequest(pollPayload, 80, false, ("GET / HTTP/1.1\r\nHost: " + pollPayload + "\r\n\r\n").getBytes());
	            for (IBurpCollaboratorInteraction interaction: context.fetchCollaboratorInteractionsFor(pollPayload)) {
	                client_ips.add(interaction.getProperty("client_ip"));
	            }
	            stdout.println("Calculated your IPs: "+ client_ips.toString());
	        }
	        catch (NullPointerException e) {
	        	stdout.println("Unable to calculate client IP - collaborator may not be functional");
	        }
	        catch (java.lang.IllegalArgumentException e) {
	        	stdout.println("The Collaborator appears to be misconfigured. Please run a health check via Project Options->Misc. Also, note that Collaborator Everywhere does not support the IP-address mode.");
	        }
	        return client_ips;

	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse content) {
	
		List<IScanIssue> issues = new ArrayList<IScanIssue>();
		
		if (callback.isInScope(helpers.analyzeRequest(content).getUrl())) {
			// Run the detection analysis
			this.RunDetectionAnalysis(content, issues);
		}
		
		if (!issues.isEmpty()) {
			return issues;
		}
		
        return null;

	}
	
	
	public void RunDetectionAnalysis(IHttpRequestResponse content, List<IScanIssue> issues) {
		
		
		// TODO Auto-generated method stub
		byte[] request = content.getRequest();
		IHttpService service = content.getHttpService();
		IRequestInfo reqInfo = helpers.analyzeRequest(request);
		
		if (reqInfo.getMethod().equals("GET")) {
			RunTestOnParameters("GET", issues, reqInfo,  content, request, service);
			RunTestOnXForwarded("GET", issues, reqInfo, content, service);
			RunTestOnHostHeader("GET", issues, reqInfo, content, service);
			RunTestInUserAgent("GET", issues, reqInfo, content, service);
			RunTestInPath("GET", issues, reqInfo, content, service);
			RunTestInReferer("GET", issues, reqInfo, content, service);
		}
		
		if (reqInfo.getMethod().equals("POST")) {
			RunTestOnParameters("POST", issues, reqInfo, content, request, service);
			RunTestOnXForwarded("POST", issues, reqInfo, content, service);
			RunTestOnHostHeader("POST", issues, reqInfo, content, service);
			RunTestInUserAgent("POST", issues, reqInfo, content, service);
			RunTestInPath("POST", issues, reqInfo, content, service);
			RunTestInReferer("POST", issues, reqInfo, content, service);
		}
	}
	
	
	// Run Tests on All Parameters
	public void RunTestOnParameters(String method, 
			List<IScanIssue> issues, 
			IRequestInfo reqInfo, 
			IHttpRequestResponse content, 
			byte[] request,
			IHttpService service) {
	
		
		URL url = helpers.analyzeRequest(content).getUrl();
		String path = reqInfo.getHeaders().get(0);
		String host = reqInfo.getHeaders().get(1);
		List<IParameter> params = reqInfo.getParameters();
		byte paramType = IParameter.PARAM_URL;
		
		// Fetch all parameters and inject our payload.
		for(int i=0; i < params.size(); i++) {
			IParameter param = params.get(i);
			
			// Build the request and update each part of the request with the payload
	       	IParameter newParam = helpers.buildParameter(param.getName(), payload, paramType);
			if(param.getType() != IParameter.PARAM_COOKIE && !param.getName().contains("_csrf")) {
				request = helpers.updateParameter(request, newParam);
			             	
		
				callback.makeHttpRequest(content.getHttpService(), request);
			    for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			    	 String client_ip = interaction.getProperty("client_ip");
			        	
			    	 if (client_ips.contains(client_ip)) {
			    		 stdout.println("Open Redirect Found");
			    		 stdout.println("IP: " + client_ip);
				         stdout.println("Host: " + host);
				         stdout.println("Path: " + path);
				         stdout.println("Method: " + method);
				        	
				         String title="Url Redirection";
				         String message="<br>EndPoint:</br><b> " + path + "</b>n";
				         CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				         issues.add(issue);
				        	
				         callback.addScanIssue(issue);
				        	
			    	 }else {
			        	
			        	 stdout.println("Found SSRF");
				         stdout.println("IP: " + client_ip);
				         stdout.println("Host: " + host);
				         stdout.println("Path: " + path);
				         stdout.println("Method: " + method);
				         
				         String title="Parameter Based SSRF";
						 String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Parameter</b>\n";
				         CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				         issues.add(issue);
				        	
				         callback.addScanIssue(issue);
			    	 }
			    }    
			}
		}
	}
	
	
	// Run Tests on All Parameters
	public void RunTestOnXForwarded(String method,
			List<IScanIssue> issues, 
			IRequestInfo reqInfo, 
			IHttpRequestResponse content, 
			IHttpService service) {
		
		URL url = helpers.analyzeRequest(content).getUrl();
		String path = reqInfo.getHeaders().get(0);
		String host = reqInfo.getHeaders().get(1);
		List<String> headers = reqInfo.getHeaders();
		headers.add("X-Forwarded-Host: " + payloadWithoutHttp);
		byte[] request = helpers.buildHttpMessage(headers, null);
				             	
			
		callback.makeHttpRequest(content.getHttpService(), request);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="X-Forwarded-Host Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>X-Forwarded-For</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
	}
	
	// Run Tests on All Parameters
	public void RunTestOnHostHeader(String method, 
			List<IScanIssue> issues, 
			IRequestInfo reqInfo, 
			IHttpRequestResponse content, 
			IHttpService service) {
		
		URL url = helpers.analyzeRequest(content).getUrl();
		String path = reqInfo.getHeaders().get(0);
		String host = reqInfo.getHeaders().get(1);
		
		List<String> headers = reqInfo.getHeaders();
		headers.set(1, "Host: " + payloadWithoutHttp);
				             	
		byte[] request = helpers.buildHttpMessage(headers, null);
		callback.makeHttpRequest(content.getHttpService(), request);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="Host Header Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Host Header</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
		
		var hostValue = host.split(" ");
		List<String> headers2 = reqInfo.getHeaders();
		headers2.set(1, "Host: " + hostValue[1] + "@" + payloadWithoutHttp);
				             	
		byte[] request2 = helpers.buildHttpMessage(headers2, null);
		callback.makeHttpRequest(content.getHttpService(), request2);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="Host Header Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Host Header</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
	}
	
	// Run Tests on All Parameters
	public void RunTestInUserAgent(String method, 
			List<IScanIssue> issues, 
			IRequestInfo reqInfo, 
			IHttpRequestResponse content, 
			IHttpService service) {
		
		URL url = helpers.analyzeRequest(content).getUrl();
		String path = reqInfo.getHeaders().get(0);
		String host = reqInfo.getHeaders().get(1);
		
		boolean foundHeader = false;
		
		List<String> headers = reqInfo.getHeaders();
		for (var i = 0; i < headers.size(); i++) {
			if (headers.get(i).contains("User-Agent")) {
				headers.set(i, "User-Agent: " + payloadWithoutHttp);
				foundHeader=true;
				break;
			}
		}
		
		if (foundHeader==false) {
			headers.add("User-Agent: " + payloadWithoutHttp);
		}
				             	
		byte[] request = helpers.buildHttpMessage(headers, null);
		callback.makeHttpRequest(content.getHttpService(), request);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="User-Agent Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>User-Agent</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
	}
	
	// Run Tests on All Parameters
	public void RunTestInReferer(String method, 
			List<IScanIssue> issues, 
			IRequestInfo reqInfo, 
			IHttpRequestResponse content, 
			IHttpService service) {
		
		URL url = helpers.analyzeRequest(content).getUrl();
		String path = reqInfo.getHeaders().get(0);
		String host = reqInfo.getHeaders().get(1);
		
		
		boolean foundHeader = false;
		List<String> headers = reqInfo.getHeaders();
		for (int i = 0; i < headers.size(); i++) {
			if (headers.get(i).contains("Referer")) {
				headers.set(i, "Referer: " + payload);
				foundHeader=true;
				break;
			}
		}
		
		if (foundHeader == false) {
			headers.add("Referer: " + payload);
		}
		
		byte[] request = helpers.buildHttpMessage(headers, null);
		
		
		callback.makeHttpRequest(content.getHttpService(), request);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="Referer Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Referer</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
	}
	
	
	// Run Tests on All Parameters
	public void RunTestInPath(String method, 
			List<IScanIssue> issues, 
			IRequestInfo reqInfo, 
			IHttpRequestResponse content, 
			IHttpService service) {
		
		URL url = helpers.analyzeRequest(content).getUrl();
		String path = reqInfo.getHeaders().get(0);
		String host = reqInfo.getHeaders().get(1);
		
		
		String[] parts =  reqInfo.getHeaders().get(0).split("");
		String finalPayload = payload+parts[1];
		String fullPath = method + " " + finalPayload;
		reqInfo.getHeaders().set(0, fullPath);
		
		List<String> headers = reqInfo.getHeaders();
				             	
		byte[] request = helpers.buildHttpMessage(headers, null);
		callback.makeHttpRequest(content.getHttpService(), request);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="Path Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Path</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
		
		
		String[] parts2 =  reqInfo.getHeaders().get(0).split("");
		String finalPayload2 = "@"+payloadWithoutHttp+parts2[1];
		String fullPath2 = method + " " + finalPayload2;
		reqInfo.getHeaders().set(0, fullPath2);
		
		List<String> headers2 = reqInfo.getHeaders();
				             	
		byte[] request2 = helpers.buildHttpMessage(headers2, null);
		callback.makeHttpRequest(content.getHttpService(), request2);
		for(IBurpCollaboratorInteraction interaction : context.fetchAllCollaboratorInteractions()) {
			String client_ip = interaction.getProperty("client_ip");
				        	
			if (client_ips.contains(client_ip)) {
				stdout.println("Open Redirect Found");
			    stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					        	
				String title="Url Redirection";
				String message="<br>EndPoint:<b> " + path + "<br>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "Low", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
					        	
			}else {
				        	
				stdout.println("Found SSRF");
				stdout.println("IP: " + client_ip);
				stdout.println("Host: " + host);
				stdout.println("Path: " + path);
				stdout.println("Method: " + method);
					         
				String title="Path Based SSRF";
				String message="<br>Method: <b>"  + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Path</b>\n";
				CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
				issues.add(issue);
					        	
				callback.addScanIssue(issue);
			}
		}
	}
	
	
	
	class CustomScanIssue implements IScanIssue {
	    private IHttpService httpService;
	    private URL url;
	    private IHttpRequestResponse[] httpMessages;
	    private String name;
	    private String detail;
	    private String severity;
	    private String confidence;
	    private String remediation;

	    CustomScanIssue(
	            IHttpService httpService,
	            URL url,
	            IHttpRequestResponse[] httpMessages,
	            String name,
	            String detail,
	            String severity,
	            String confidence,
	            String remediation) {
	        this.name = name;
	        this.detail = detail;
	        this.severity = severity;
	        this.httpService = httpService;
	        this.url = url;
	        this.httpMessages = httpMessages;
	        this.confidence = confidence;
	        this.remediation = remediation;
	    }

	    @Override
	    public URL getUrl() {
	        return url;
	    }

	    @Override
	    public String getIssueName() {
	        return name;
	    }

	    @Override
	    public int getIssueType() {
	        return 0;
	    }

	    @Override
	    public String getSeverity() {
	        return severity;
	    }

	    @Override
	    public String getConfidence() {
	        return confidence;
	    }

	    @Override
	    public String getIssueBackground() {
	        return null;
	    }

	    @Override
	    public String getRemediationBackground() {
	        return null;
	    }

	    @Override
	    public String getIssueDetail() {
	        return detail;
	    }

	    @Override
	    public String getRemediationDetail() {
	        return remediation;
	    }

	    @Override
	    public IHttpRequestResponse[] getHttpMessages() {
	        return httpMessages;
	    }

	    @Override
	    public IHttpService getHttpService() {
	        return httpService;
	    }

//	    @Override
	    public String getHost() {
	        return null;
	    }

//	    @Override
	    public int getPort() {
	        return 0;
	    }

//	    @Override
	    public String getProtocol() {
	        return null;
	    }
	}

}