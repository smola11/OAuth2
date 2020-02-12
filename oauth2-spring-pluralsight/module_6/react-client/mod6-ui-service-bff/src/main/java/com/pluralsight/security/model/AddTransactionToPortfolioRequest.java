package com.pluralsight.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddTransactionToPortfolioRequest {

    private String cryptoSymbol;
    private String quantity;
    private String price;
    @JsonProperty("transactionType")
    private String transactionType;
    private String username;
}
