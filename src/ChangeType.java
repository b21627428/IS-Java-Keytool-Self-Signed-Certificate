public enum ChangeType {
    DELETED("deleted"),
    ALTERED("altered"),
    CREATED("created");

    private String name;

    ChangeType(String name){
        this.name = name;
    }
    public String getName(){
        return this.name;
    }
}
