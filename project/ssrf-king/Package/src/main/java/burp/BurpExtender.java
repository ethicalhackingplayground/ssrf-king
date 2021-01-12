package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.Date;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;


import tabs.SSRFTabFactory;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IScannerCheck {
	private SSRFTabFactory factory;
    private IBurpCollaboratorClientContext context;
    private PrintWriter stdout;
    public IBurpExtenderCallbacks callback;
	public IExtensionHelpers helpers;
	public String payload;
	private HashSet<String> client_ips;
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	stdout = new PrintWriter(callbacks.getStdout(), true);
    	this.callback=callbacks;
    	helpers=callbacks.getHelpers();
        callbacks.setExtensionName("SSRF-King 1.1");
        factory=new SSRFTabFactory(callbacks);
        callbacks.registerMessageEditorTabFactory(factory);

        stdout.println("Contributor:\n\tBlake (zoid) (twitter.com/z0idsec)\n\t");
        stdout.println("Installation complete.");
        context=callbacks.createBurpCollaboratorClientContext();
        payload="http://"+context.generatePayload(true);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerScannerCheck(this);
        
        stdout.println("Payload: " + payload);
        
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
			
			
			// TODO Auto-generated method stub
			byte[] request = content.getRequest();
			IHttpService service = content.getHttpService();
			IRequestInfo reqInfo = helpers.analyzeRequest(request);
			URL url = helpers.analyzeRequest(content).getUrl();
			stdout.println("Url: " + url);
			String path = reqInfo.getHeaders().get(0);
			String host = reqInfo.getHeaders().get(1);
	        List<IParameter> params = reqInfo.getParameters();
	        byte paramType = reqInfo.getMethod().equals("GET")? IParameter.PARAM_URL : IParameter.PARAM_BODY;
	         
	        // sql injection payloads
	        for(int i=0; i < params.size(); i++) {
	        	IParameter param = params.get(i);
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
	    		        	String title="Server Side Request Forgery";
	    		        	String message="<br>EndPoint:<b> " + path + "<br>\n";
	    		        	CustomScanIssue issue=new CustomScanIssue(service, url, new IHttpRequestResponse[]{content} , title, message, "High", "Certain", "Panic");
	    		        	issues.add(issue);
	    		        	
	    		        	callback.addScanIssue(issue);
	    	        	}
	    	        }
	         	}
	        }
		}
		
		if (!issues.isEmpty()) {
			return issues;
		}
		
        return null;

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

    class SSRFTabFactory implements IMessageEditorTabFactory{

		private IBurpExtenderCallbacks callbacks;
		private IExtensionHelpers helpers;
	    private PrintWriter stdout;
		
		
	    public SSRFTabFactory(IBurpExtenderCallbacks callbacks) {
	    	this.callbacks = callbacks;
	        helpers = callbacks.getHelpers();
	        stdout = new PrintWriter(callbacks.getStdout(), true);
	    }
    
	    @Override
		public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
	    {
	        return new SQLTab(controller, editable);
	    }
	}

	class SQLTab implements IMessageEditorTab{
		private boolean editable;
		private ITextEditor txtInput;
		private byte[] currentMessage;
	
		public SQLTab(IMessageEditorController controller, boolean editable)
		{
			this.editable = editable;
			txtInput = callback.createTextEditor();
			txtInput.setEditable(editable);
		}
	
		@Override
		public String getTabCaption()
		{
			return "SSRF";
		}
	
		@Override
		public Component getUiComponent()
		{
			return txtInput.getComponent();
		}
	
		@Override
		public boolean isEnabled(byte[] content, boolean isRequest)
		{
			return isRequest;
		}
	
		@Override
		public void setMessage(byte[] content, boolean isRequest)
		{
			if (content == null)
			{
				txtInput.setText(null);
				txtInput.setEditable(false);
			}else{
				IRequestInfo reqInfo = helpers.analyzeRequest(content);
				List<IParameter> params = reqInfo.getParameters();
				byte paramType = reqInfo.getMethod().equals("GET")? IParameter.PARAM_URL : IParameter.PARAM_BODY;
	                
				// sql injection payloads
				for(int i=0; i < params.size(); i++) {
	                IParameter param = params.get(i);
	                IParameter newParam = helpers.buildParameter(param.getName(), payload, paramType);
	                if(param.getType() != IParameter.PARAM_COOKIE && !param.getName().contains("_csrf")) {
		                content = helpers.updateParameter(content, newParam);
	                }
				}
	
				txtInput.setText(content);
				txtInput.setEditable(editable);
			}
			// remember the displayed content
			currentMessage = content;
			
			
		}
	
		@Override
		public byte[] getMessage()
		{
			return currentMessage;
		}
	
		@Override
		public boolean isModified()
		{
			//return txtInput.isTextModified();
			return false; //always
		}
	
		@Override
		public byte[] getSelectedData()
		{
			return txtInput.getSelectedText();
		}
	}
}