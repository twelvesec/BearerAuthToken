package burp;
import java.awt.Component;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import org.json.JSONException;
import org.json.JSONObject;

public class BurpExtender extends AbstractTableModel implements ISessionHandlingAction ,ITab, IMessageEditorController
{
    private static final long serialVersionUID = 1L;
        private IBurpExtenderCallbacks callbacks;
	    private IExtensionHelpers helpers;
	        private PrintWriter stdout;
		    private String date;
		        ArrayList headers = new ArrayList();
			    private final List log = new ArrayList();
			        private JSplitPane splitPane;
				    private IMessageEditor requestViewer;
				        private IMessageEditor responseViewer;
						private String NAME = "Bearer Token";    

						    private IHttpRequestResponse currentlyDisplayedItem;
						        
							    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
							        {
								        this.callbacks = callbacks;
									        // set our extension name
										        callbacks.setExtensionName("Authorization Token");        
											        // obtain an extension helpers object
												        helpers = callbacks.getHelpers();
													      
													              // obtain our output and error streams
														              stdout = new PrintWriter(callbacks.getStdout(), true);

															              SimpleDateFormat sdf = new SimpleDateFormat("dd-M-yyyy hh:mm:ss");
																              date = sdf.format(new Date());
																	              // obtain our output and error streams
																		              PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
																			                    
																					            // write a message to our output stream
																						            stdout.println("Authorization Token\n");
																							            stdout.println("starting at time : " + date);
																								            stdout.println("-----------------------------------------------------------------\n\n");
																									         
																										         SwingUtilities.invokeLater(new Runnable() 
																											         {
																												             @Override
																													                 public void run()
																															             {
																																                     // main split pane
																																		                     splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
																																				                             
																																							                     // table of log entries
																																									                     Table logTable = new Table(BurpExtender.this);
																																											                     JScrollPane scrollPane = new JScrollPane(logTable);
																																													                     splitPane.setLeftComponent(scrollPane);

																																															                     // tabs with request/response viewers
																																																	                     JTabbedPane tabs = new JTabbedPane();
																																																			                     requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
																																																					                     responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
																																																							                     tabs.addTab("Request", requestViewer.getComponent());
																																																									                     tabs.addTab("Response", responseViewer.getComponent());
																																																											                     
																																																													                     splitPane.setRightComponent(tabs);

																																																															                     // customize our UI components
																																																																	                     callbacks.customizeUiComponent(splitPane);
																																																																			                     callbacks.customizeUiComponent(logTable);
																																																																					                     callbacks.customizeUiComponent(scrollPane);
																																																																							                     callbacks.customizeUiComponent(tabs);
																																																																									                     
																																																																											                     // add the custom tab to Burp's UI
																																																																													                     callbacks.addSuiteTab(BurpExtender.this);
																																																																															                     
																																																																																	                     //register the handler that does that alters the HTTP request
																																																																																			                     //this has to be enabled via the Burp Session handling options
																																																																																					                     callbacks.registerSessionHandlingAction(BurpExtender.this);
																																																																																							                     
																																																																																									                 }
																																																																																											         });
																																																																																												     }
																																																																																												         
																																																																																													     @Override
																																																																																													         public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
																																																																																														         
																																																																																															         IRequestInfo rqInfo = helpers.analyzeRequest(currentRequest);
																																																																																																         IResponseInfo macro_repsonse_items = helpers.analyzeResponse(macroItems[0].getResponse());
																																																																																																	         byte[] macro_msg = macroItems[0].getResponse();
																																																																																																		         String Response = helpers.bytesToString(macro_msg);
																																																																																																			         String Resp_Body = Response.substring(macro_repsonse_items.getBodyOffset());
																																																																																																				        JSONObject json;
																																																																																																					    try {
																																																																																																					            json = new JSONObject(Resp_Body);
																																																																																																						            boolean bearer_token = json.has("bearerToken");
																																																																																																							            String Bearer = null; 
																																																																																																								            if (bearer_token == true)
																																																																																																									                Bearer = json.getString("bearerToken");
																																																																																																											            
																																																																																																												             // retrieve all headers
																																																																																																													             headers = (ArrayList) rqInfo.getHeaders();
																																																																																																														             
																																																																																																															             // get the request
																																																																																																																             String request = new String(currentRequest.getRequest());
																																																																																																																	             
																																																																																																																		             // get the request body 
																																																																																																																			             String messageBody = request.substring(rqInfo.getBodyOffset());
																																																																																																																				             
																																																																																																																					             // go through the header and look for the one that we want to replace
																																																																																																																						             for (int i = 0; i < headers.size(); i++){
																																																																																																																							                if(((String) headers.get(i)).startsWith("Authorization: Bearer "))
																																																																																																																									                 headers.remove(i);
																																																																																																																											                             
																																																																																																																														             }          
																																																																																																																															             
																																																																																																																																             headers.add("Authorization: Bearer " + Bearer);   
																																																																																																																																	             // create the new http message with the modified header
																																																																																																																																		             byte[] message = helpers.buildHttpMessage(headers, messageBody.getBytes());
																																																																																																																																			             
																																																																																																																																				             // replace the current request and forward it
																																																																																																																																					             synchronized(log)
																																																																																																																																						             {
																																																																																																																																							                 int row =log.size();
																																																																																																																																									             log.add(new LogEntry("adding new header  - Authorization bearer: " + Bearer,"Header Checked at time : " + date, callbacks.saveBuffersToTempFiles(currentRequest)));
																																																																																																																																										                 log.add(new LogEntry("","-----------------------------------------------------------------", callbacks.saveBuffersToTempFiles(currentRequest)));
																																																																																																																																												             log.add(new LogEntry("Geting authorized..done\n\n","", callbacks.saveBuffersToTempFiles(currentRequest)));
																																																																																																																																													                 log.add(new LogEntry("-----------------------------------------------------------------\n\n","", callbacks.saveBuffersToTempFiles(currentRequest)));
																																																																																																																																															             fireTableRowsInserted(row,row);
																																																																																																																																																             }
																																																																																																																																																	             
																																																																																																																																																		             currentRequest.setRequest(message);  
																																																																																																																																																			           
																																																																																																																																																				       } catch (JSONException e) {
																																																																																																																																																				            
																																																																																																																																																					            e.printStackTrace();
																																																																																																																																																						        }     
																																																																																																																																																							    }

																																																																																																																																																							        @Override
																																																																																																																																																								    public String getActionName() {
																																																																																																																																																								         
																																																																																																																																																									         return NAME;
																																																																																																																																																										     }
																																																																																																																																																										         
																																																																																																																																																											      @Override
																																																																																																																																																											              public String getColumnName(int columnIndex)
																																																																																																																																																												              {
																																																																																																																																																													                  switch (columnIndex)
																																																																																																																																																															              {
																																																																																																																																																																                      case 0:
																																																																																																																																																																		                          return "Checked Time";
																																																																																																																																																																					                  case 1:
																																																																																																																																																																							                      return "Outline";
																																																																																																																																																																									                      default:
																																																																																																																																																																											                          return "";
																																																																																																																																																																														              }
																																																																																																																																																																															              }

																																																																																																																																																																																          @Override
																																																																																																																																																																																	      public int getColumnCount() {
																																																																																																																																																																																	              
																																																																																																																																																																																		              return 2;
																																																																																																																																																																																			          }

																																																																																																																																																																																				      @Override
																																																																																																																																																																																				          public int getRowCount() {
																																																																																																																																																																																					          
																																																																																																																																																																																						          return log.size();
																																																																																																																																																																																							      }

																																																																																																																																																																																							          @Override
																																																																																																																																																																																								      public Object getValueAt(int rowIndex, int columnIndex)
																																																																																																																																																																																								          {
																																																																																																																																																																																									          LogEntry logEntry = (LogEntry) log.get(rowIndex);

																																																																																																																																																																																										          switch (columnIndex)
																																																																																																																																																																																											          {
																																																																																																																																																																																												              case 0:
																																																																																																																																																																																													                       return logEntry.Checked_Time;
																																																																																																																																																																																															                   case 1:
																																																																																																																																																																																																	                   return logEntry.Outline;
																																																																																																																																																																																																			               default:
																																																																																																																																																																																																				                       return "";
																																																																																																																																																																																																						               }
																																																																																																																																																																																																							           }

																																																																																																																																																																																																								       @Override
																																																																																																																																																																																																								           public IHttpService getHttpService() {
																																																																																																																																																																																																									           // TODO Auto-generated method stub
																																																																																																																																																																																																										           return null;
																																																																																																																																																																																																											       }

																																																																																																																																																																																																											           @Override
																																																																																																																																																																																																												       public byte[] getRequest() {
																																																																																																																																																																																																												               return currentlyDisplayedItem.getRequest();
																																																																																																																																																																																																													           }

																																																																																																																																																																																																														       @Override
																																																																																																																																																																																																														           public byte[] getResponse() {
																																																																																																																																																																																																															           return currentlyDisplayedItem.getResponse();
																																																																																																																																																																																																																       }

																																																																																																																																																																																																																           @Override
																																																																																																																																																																																																																	       public String getTabCaption() {
																																																																																																																																																																																																																	               return "Bearer";
																																																																																																																																																																																																																		           }

																																																																																																																																																																																																																			       @Override
																																																																																																																																																																																																																			           public Component getUiComponent() {
																																																																																																																																																																																																																				           return splitPane;
																																																																																																																																																																																																																					       }
																																																																																																																																																																																																																					           
																																																																																																																																																																																																																						       @Override
																																																																																																																																																																																																																						           public Class getColumnClass(int columnIndex)
																																																																																																																																																																																																																							       {
																																																																																																																																																																																																																							               return String.class;
																																																																																																																																																																																																																								           }

																																																																																																																																																																																																																									       private class Table extends JTable
																																																																																																																																																																																																																									           {

																																																																																																																																																																																																																										           private static final long serialVersionUID = 1L;

																																																																																																																																																																																																																											           public Table(TableModel tableModel)
																																																																																																																																																																																																																												           {
																																																																																																																																																																																																																													               super(tableModel);
																																																																																																																																																																																																																														               }
																																																																																																																																																																																																																															          
																																																																																																																																																																																																																																          
																																																																																																																																																																																																																																	          @Override
																																																																																																																																																																																																																																		          public void changeSelection(int row, int col, boolean toggle, boolean extend)
																																																																																																																																																																																																																																			          {
																																																																																																																																																																																																																																				              // show the log entry for the selected row
																																																																																																																																																																																																																																					                  LogEntry logEntry = (LogEntry) log.get(row);
																																																																																																																																																																																																																																							              requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
																																																																																																																																																																																																																																								                  responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
																																																																																																																																																																																																																																										              currentlyDisplayedItem = logEntry.requestResponse;
																																																																																																																																																																																																																																											                  super.changeSelection(row, col, toggle, extend);
																																																																																																																																																																																																																																													          } 
																																																																																																																																																																																																																																														      
																																																																																																																																																																																																																																														          }
																																																																																																																																																																																																																																															          private static class LogEntry
																																																																																																																																																																																																																																																          {
																																																																																																																																																																																																																																																	              final IHttpRequestResponsePersisted requestResponse;
																																																																																																																																																																																																																																																		                  final String Outline;
																																																																																																																																																																																																																																																				              final String Checked_Time;

																																																																																																																																																																																																																																																					                  LogEntry(String Outline,String Checked_Time, IHttpRequestResponsePersisted requestResponse)
																																																																																																																																																																																																																																																							              {
																																																																																																																																																																																																																																																								                     this.requestResponse = requestResponse;
																																																																																																																																																																																																																																																										                    this.Outline = Outline;
																																																																																																																																																																																																																																																												                   this.Checked_Time = Checked_Time;
																																																																																																																																																																																																																																																														               }
																																																																																																																																																																																																																																																															               }
																																																																																																																																																																																																																																																																           }
