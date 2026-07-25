namespace Backend.Models.Model;

public class paginatedResponse<T>
{
    public T[] data { get; set; }
    public int totalCount { get; set; }
    public int pageNumber { get; set; }
    public int pageSize { get; set; }
}