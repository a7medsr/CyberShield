namespace CyberBrief.DTOs.Container;

public class summaryDto
{
   public string Id{get;set;}
  public  string ImageName{get;set;}
  public  DateTime StartedAt{get;set;}
  public  DateTime FinishedAt{get;set;}
  public  int TotalVulnerabilities{get;set;}
  public  int CriticalVulnerabilities{get;set;}
  public  int HighetVulnerabilities{get;set;}
   public int MediumVulnerabilities{get;set;}
  public  int LowetVulnerabilities{get;set;}
   public List<VulnerabilityDto>?Vulnerabilities{get;set;}
    
}