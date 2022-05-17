package com.sha.springbootjwtauthorization.service;

import com.sha.springbootjwtauthorization.model.Purchase;
import com.sha.springbootjwtauthorization.repository.projection.PurchaseItem;

import java.util.List;

public interface PurchaseService
{
    Purchase savePurchase(Purchase purchase);

    List<PurchaseItem> findPurchaseItemsOfUser(Long userId);
}